/*
 * Copyright © 2025, 2026 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.core.path;

import tech.kwik.core.cid.ConnectionIdProvider;
import tech.kwik.core.frame.NewConnectionIdFrame;
import tech.kwik.core.frame.Padding;
import tech.kwik.core.frame.PathChallengeFrame;
import tech.kwik.core.frame.PathResponseFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.send.SenderImpl;
import tech.kwik.core.socket.ServerConnectionSocketManager;
import tech.kwik.core.util.OneShotRateLimiter;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;


public class PathValidator {

    private static final Random randomGenerator = new SecureRandom();
    private final VersionHolder version;
    private volatile InetSocketAddress currentAddress;
    private final SenderImpl sender;
    private final ConnectionIdProvider connectionIdProvider;
    private final Logger logger;
    private final ServerConnectionSocketManager socketManager;
    private final Clock clock;
    private final Map<Long, PathValidation> pathValidationsByChallenge;
    private final Map<InetSocketAddress, PathValidation> pathValidationsByAddress;
    private final ScheduledExecutorService executor;
    private volatile long highestReceivedPacketNumber;
    private volatile Instant currentAddressLastUsed;
    // The last validated peer address; sending reverts to this address when validation of a new peer address fails.
    private volatile InetSocketAddress lastValidatedAddress;
    // Number of the last datagram counted for the anti-amplification limit, so that coalesced packets are counted once.
    private volatile int lastCountedDatagramNumber = -1;
    private final boolean peerUsesNonZeroLengthConnectionIDs;
    private OneShotRateLimiter logOncePerAddressRateLimiter;

    public PathValidator(VersionHolder version, InetSocketAddress clientAddress, SenderImpl sender, ServerConnectionSocketManager socketManager, ConnectionIdProvider connectionIdProvider, Logger logger) {
        this(Executors.newSingleThreadScheduledExecutor(), version, clientAddress, sender, socketManager, Clock.systemUTC(), connectionIdProvider, logger);
    }

    public PathValidator(ScheduledExecutorService executor, VersionHolder version, InetSocketAddress clientAddress, SenderImpl sender,
                         ServerConnectionSocketManager socketManager, Clock clock, ConnectionIdProvider connectionIdProvider, Logger logger) {
        this.version = version;
        currentAddress = clientAddress;
        lastValidatedAddress = clientAddress;
        this.sender = sender;
        this.connectionIdProvider = connectionIdProvider;
        this.logger = logger;
        this.socketManager = socketManager;
        this.clock = clock;
        pathValidationsByChallenge = new ConcurrentHashMap<>();
        pathValidationsByAddress = new ConcurrentHashMap<>();
        this.executor = executor;
        peerUsesNonZeroLengthConnectionIDs = !connectionIdProvider.peerUsesZeroLengthConnectionId();

        pathValidationsByAddress.put(clientAddress, PathValidation.preValidated(clientAddress, clock.instant()));
        logOncePerAddressRateLimiter = new OneShotRateLimiter(2);
    }

    public synchronized void checkSourceAddress(QuicPacket packet, PacketMetaData metaData) {
        highestReceivedPacketNumber = Long.max(highestReceivedPacketNumber, packet.getPacketNumber());
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-9.3
        // "Receiving a packet from a new peer address containing a non-probing frame indicates that the peer has migrated to that address."
        // "An endpoint only changes the address to which it sends packets in response to the highest-numbered non-probing packet."
        boolean highestNumberedNonProbing = !isProbingPacket(packet) && packet.getPacketNumber() == highestReceivedPacketNumber;

        InetSocketAddress packetSourceAddress = metaData.sourceAddress();

        if (!packetSourceAddress.equals(currentAddress)) {

            if (isValidated(packetSourceAddress)) {
                if (highestNumberedNonProbing) {
                    logger.info("Receiving non-probing packet on new (validated) path; migrating connection to " + packetSourceAddress);
                    migrateConnection(packetSourceAddress);
                }
            }
            else if (pathValidationInProgress(packetSourceAddress)) {
                // Validation might have been started by a probing packet, while the peer now actually migrates.
                if (highestNumberedNonProbing) {
                    sendToUnvalidatedAddress(packetSourceAddress, metaData);
                }
            }
            else {
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-9.3
                // "If the recipient has no unused connection IDs from the peer, it will not be able to send anything on
                //  the new path until the peer provides one; ..."
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-9.5
                // "An endpoint that exhausts available connection IDs cannot probe new paths or initiate migration, nor
                //  can it respond to probes or attempts by its peer to migrate."
                if (! hasUnusedPeerConnectionIDs() && peerUsesNonZeroLengthConnectionIDs) {
                    logOncePerAddressRateLimiter.execute(packetSourceAddress, () ->
                            logger.info(String.format("Potential address migration? %s -> %s, but cannot start path validation due to lack of unused peer connection IDs",
                                    currentAddress, packetSourceAddress)));
                }
                else {
                    // https://www.rfc-editor.org/rfc/rfc9000.html#section-9
                    // "An endpoint MUST perform path validation (Section 8.2) if it detects any change to a peer's address, "
                    logger.info(String.format("Potential address migration? %s -> %s; starting path validation", currentAddress, packetSourceAddress));
                    startValidation(packet, packetSourceAddress);
                    if (highestNumberedNonProbing) {
                        sendToUnvalidatedAddress(packetSourceAddress, metaData);
                    }
                }
            }
        }
        else {
            currentAddressLastUsed = clock.instant();
            if (! isValidated(currentAddress)) {
                countForAntiAmplificationLimit(metaData);
            }
        }
    }

    private void sendToUnvalidatedAddress(InetSocketAddress newAddress, PacketMetaData metaData) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-9.3
        // "If the recipient permits the migration, it MUST send subsequent packets to the new peer address and MUST
        //  initiate path validation (Section 8.2) to verify the peer's ownership of the address if validation is not
        //  already underway."
        // "An endpoint MAY send data to an unvalidated peer address, but it MUST protect against potential attacks as
        //  described in Sections 9.3.1 and 9.3.2."
        // Waiting for the validation to succeed before sending to the new address can deadlock: when the peer's
        // congestion window is filled with packets that were lost, it will not send the PATH_RESPONSE until it receives
        // acknowledgements, which would not arrive as long as they are sent to the old address.
        logger.info("Receiving non-probing packet on new (not yet validated) path; sending to " + newAddress + " while validating it");
        InetSocketAddress previousAddress = currentAddress;
        rememberLastUse(previousAddress);
        socketManager.changeClientAddress(newAddress);
        currentAddress = newAddress;
        currentAddressLastUsed = clock.instant();
        if (! previousAddress.equals(lastValidatedAddress)) {
            // The previous address was not validated either, so it is not the one to revert to.
            connectionIdProvider.addressNoLongerInUse(previousAddress);
        }

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-9.3.1
        // "Until a peer's address is deemed valid, an endpoint limits the amount of data it sends to that address"
        lastCountedDatagramNumber = metaData.datagramNumber();
        sender.limitSendingToUnvalidatedAddress(metaData.getDatagramSize());
    }

    private void countForAntiAmplificationLimit(PacketMetaData metaData) {
        if (metaData.datagramNumber() != lastCountedDatagramNumber) {
            lastCountedDatagramNumber = metaData.datagramNumber();
            sender.increaseUnvalidatedAddressLimit(metaData.getDatagramSize());
        }
    }

    private boolean hasUnusedPeerConnectionIDs() {
        return connectionIdProvider.unusedPeerConnectionIdAvailable();
    }

    private void startValidation(QuicPacket packet, InetSocketAddress packetSourceAddress) {
        PathValidation validation = new PathValidation(packetSourceAddress, isProbingPacket(packet), clock.instant());
        pathValidationsByAddress.put(packetSourceAddress, validation);

        doValidation(validation);

        purgeOldValidations();
    }

    private synchronized void doValidation(PathValidation validation) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.1
        // "An endpoint SHOULD NOT probe a new path with packets containing a PATH_CHALLENGE frame more frequently
        //  than it would send an Initial packet. "
        int initialPto = 1000;
        int delay = initialPto * (int) (Math.pow(2, validation.getChallengeRepeatCount()));

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.4
        // "Endpoints SHOULD abandon path validation based on a timer."
        if (clock.instant().isAfter(validation.startedAt().plusMillis((long) (3 * initialPto * 1.05f)))) {
            logger.info("Path validation failed for " + validation.getAddressToValidate() + " after " + validation.getChallengeRepeatCount() + " attempts and timeout of " + (3 * initialPto) + "ms");
            remove(validation);
            if (validation.getAddressToValidate().equals(currentAddress)) {
                revertToLastValidatedAddress();
            }
        }
        else {
            byte[] challenge = generateChallenge();
            pathValidationsByChallenge.put(convertToLong(challenge), validation);
            PathChallengeFrame pathChallengeFrame = new PathChallengeFrame(version.getVersion(), challenge);
            sender.sendAlternateAddress(pathChallengeFrame, validation.getAddressToValidate());
            validation.incrementChallengeRepeatCount();

            // And schedule the next check
            executor.schedule(() -> {
                if (validation.isInProgress()) {
                    doValidation(validation);
                }
            }, delay, java.util.concurrent.TimeUnit.MILLISECONDS);
        }
    }

    private void remove(PathValidation validation) {
        pathValidationsByAddress.remove(validation.getAddressToValidate());
        pathValidationsByChallenge.values().removeIf(v -> v == validation);
    }

    private void purgeOldValidations() {
        pathValidationsByAddress.values().stream()
                .sorted(Comparator.reverseOrder())
                .skip(10)
                .forEach(this::remove);
    }

    private boolean pathValidationInProgress(InetSocketAddress address) {
        PathValidation validation = pathValidationsByAddress.get(address);
        return validation != null && validation.isInProgress();
    }

    private void migrateConnection(InetSocketAddress newAddress) {
        InetSocketAddress previousAddress = currentAddress;
        socketManager.changeClientAddress(newAddress);
        rememberLastUse(previousAddress);

        currentAddress = newAddress;
        currentAddressLastUsed = null;
        lastValidatedAddress = newAddress;
        // The new address is validated, so sending to it must not be limited.
        sender.unsetAntiAmplificationLimit();

        // let connection id manager know that the previous address is no longer in use, so it can retire the connection id associated with it
        connectionIdProvider.addressNoLongerInUse(previousAddress);
    }

    private void completeMigration(InetSocketAddress validatedAddress) {
        InetSocketAddress previousValidatedAddress = lastValidatedAddress;
        lastValidatedAddress = validatedAddress;
        sender.unsetAntiAmplificationLimit();
        if (! validatedAddress.equals(previousValidatedAddress)) {
            connectionIdProvider.addressNoLongerInUse(previousValidatedAddress);
        }
    }

    private void revertToLastValidatedAddress() {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-9.3.2
        // "To protect the connection from failing due to such a spurious migration, an endpoint MUST revert to using
        //  the last validated peer address when validation of a new peer address fails."
        InetSocketAddress failedAddress = currentAddress;
        logger.info("Reverting to last validated address " + lastValidatedAddress + " after failed validation of " + failedAddress);
        socketManager.changeClientAddress(lastValidatedAddress);
        currentAddress = lastValidatedAddress;
        currentAddressLastUsed = null;
        sender.unsetAntiAmplificationLimit();
        connectionIdProvider.addressNoLongerInUse(failedAddress);
    }

    private void rememberLastUse(InetSocketAddress address) {
        PathValidation validation = pathValidationsByAddress.get(address);
        if (validation != null) {
            validation.setAddressLastUsed(currentAddressLastUsed);
        }
    }

    private byte[] generateChallenge() {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.1
        // "The endpoint MUST use unpredictable data in every PATH_CHALLENGE frame so that it can associate the peer's
        //  response with the corresponding PATH_CHALLENGE."
        byte[] data = new byte[8];
        randomGenerator.nextBytes(data);
        return data;
    }

    private Long convertToLong(byte[] challenge) {
        assert challenge.length == 8;
        return ByteBuffer.wrap(challenge).getLong();
    }

    static boolean isProbingPacket(QuicPacket packet) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-9.1
        // "A packet containing only probing frames is a "probing packet", and a packet containing any other frame is a "non-probing packet"."
        return packet.getFrames().stream().allMatch(PathValidator::isProbingFrame);
    }

    static boolean isProbingFrame(QuicFrame frame) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-9.1
        // "PATH_CHALLENGE, PATH_RESPONSE, NEW_CONNECTION_ID, and PADDING frames are "probing frames", and all other frames are "non-probing frames".
        return frame instanceof PathChallengeFrame ||
                frame instanceof PathResponseFrame ||
                frame instanceof NewConnectionIdFrame ||
                frame instanceof Padding;
    }

    public synchronized void checkPathResponse(PathResponseFrame pathResponseFrame, PacketMetaData metaData) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.3
        // "Path validation succeeds when a PATH_RESPONSE frame is received that contains the data that was sent in a
        //  previous PATH_CHALLENGE frame. A PATH_RESPONSE frame received on any network path validates the path on
        //  which the PATH_CHALLENGE was sent."
        Long challenge = convertToLong(pathResponseFrame.getData());
        if (pathValidationsByChallenge.containsKey(challenge)) {
            PathValidation pathValidation = pathValidationsByChallenge.remove(challenge);
            pathValidation.setValidated();
            InetSocketAddress validatedAddress = pathValidation.getAddressToValidate();
            logger.info("Path validated: " + validatedAddress);
            if (validatedAddress.equals(currentAddress)) {
                // Already sending to this address since the non-probing packet that triggered the validation; now that
                // it is validated, sending is no longer limited and the previous address is no longer needed.
                logger.info("Migration to validated address completed: " + validatedAddress);
                completeMigration(validatedAddress);
            }
        }
        else {
            logger.info("Received unexpected path response: " + pathResponseFrame);
        }
    }

    public boolean isValidated(InetSocketAddress newAddress) {
        PathValidation validation = pathValidationsByAddress.get(newAddress);
        return validation != null && validation.isValidated(clock.instant());
    }
}
