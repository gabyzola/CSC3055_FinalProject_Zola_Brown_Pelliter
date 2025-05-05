package pqcrypto;

import java.time.Instant;

/** helper class for AuthManager
 * represents information about an active session
 */
public class SessionInfo {
    public final String username;
    public final long startTime;
    public final long expiryTime; 
    public boolean totpVerified;

    /**
     * basic constructor 
     * @param username
     * @param sessionDurationMinutes
     */
    public SessionInfo(String username, int sessionDurationMinutes) {
        this.username = username;
        this.startTime = Instant.now().getEpochSecond();
        this.expiryTime = this.startTime + (sessionDurationMinutes * 60);
        this.totpVerified = false;
    }

    public boolean isExpired() {
        return Instant.now().getEpochSecond() > this.expiryTime;
    }
}
