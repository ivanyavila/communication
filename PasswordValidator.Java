import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PasswordValidator {

    private static final String API_URL = "https://api.pwnedpasswords.com/range/";

    /**
     * Validates a password by checking its hash against the Pwned Passwords API.
     *
     * @param password The password to validate.
     * @return The maximum count found in the response.
     */
    public int validatePassword(String password) {
        try {
            // Hash the password using SHA-1
            String sha1Hash = hashPassword(password);

            // Extract the first 5 characters of the hash (prefix)
            String prefix = sha1Hash.substring(0, 5);

            // Extract the remaining characters of the hash (suffix)
            String suffix = sha1Hash.substring(5);

            // Call the Pwned Passwords API with the prefix
            Response responseBody = callPwnedPasswordsAPI(prefix);


            // Parse the response and find the maximum count
            int maxCount = findMaxCount(responseBody.readEntity(String.class), suffix);

            return maxCount;
        } catch (Exception e) {
            e.printStackTrace();
            return -1; // Return -1 in case of an error
        }
    }

    private String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] hashBytes = sha1.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString().toUpperCase(); // Convert to uppercase as required by API
    }

    private Response callPwnedPasswordsAPI(String prefix) {
        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(API_URL + prefix);
        try {
            Response response = target.request().get();
            if (response.getStatus() != 200) {
                throw new RuntimeException("Failed to fetch data from API: HTTP " + response.getStatus());
            }
            return response;
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return Response.noContent().build();
    }

    private int findMaxCount(String responseBody, String suffix) {
        long start = System.currentTimeMillis();
        int maxCount = 0;

        String[] lines = responseBody.split("\n");
        for (String line : lines) {
            String[] parts = line.split(":");
            if (parts.length == 2 && parts[0].equals(suffix)) {
                int count = Integer.parseInt(parts[1].trim());
                maxCount = Math.max(maxCount, count);
            }
        }
        long end = System.currentTimeMillis();
        double secs = (double) ((end - start) / 1000);
        System.out.println("Time execution for findMaxCount ["+lines.length+"]: " + secs + " seconds");
        return maxCount;
    }
}
