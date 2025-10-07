package hyu.demo.reader.config;

import io.github.cdimascio.dotenv.Dotenv;
import io.github.cdimascio.dotenv.DotenvException;

import java.util.Arrays;
import java.util.List;

public class EnvConfig {
    private static final String envFileDir = "/opt/CMECF";

    private static final String[] requiredVars = {
            "OIDC_CLIENT_ID",
            "OIDC_CLIENT_SECRET",
            "OIDC_REDIRECT_URI",
            "OIDC_ISSUER_URI",
            "SERVER_PORT"
    };

    // List of sensitive keys that should not be logged
    private static final List<String> SENSITIVE_KEYS = Arrays.asList(
            "CLIENT_ID", "SECRET", "PASSWORD", "KEY", "TOKEN", "PRIVATE"
    );

    public static void loadEnvironmentVariables() {
        // Load environment variables only once
        // Skip if required variables are already set
        if (System.getProperty("OIDC_CLIENT_ID") != null) {
            System.out.println("ℹ️  Environment variables already loaded, skipping...");
            return;
        }

        try {
            Dotenv dotenv = Dotenv.configure()
                    .directory(envFileDir)
                    .filename(".env")
                    .ignoreIfMissing()
                    .load();

            // Only set the specific variables we care about from .env file
            String[] envVarsToLoad = {
                    "OIDC_CLIENT_ID",
                    "OIDC_CLIENT_SECRET",
                    "OIDC_REDIRECT_URI",
                    "OIDC_ISSUER_URI",
                    "SERVER_PORT",
                    "SPRING_PROFILES_ACTIVE",
                    "DEBUG",
                    "LOG_LEVEL"
            };

            int loadedCount = 0;
            System.out.println("🔧 Loading environment variables from .env file...");

            for (String varName : envVarsToLoad) {
                String value = dotenv.get(varName);
                if (value != null && !value.trim().isEmpty()) {
                    System.setProperty(varName, value);
                    System.out.println("✅ Loaded from .env: " + varName + " = " +
                            (isSensitive(varName) ? "***HIDDEN***" : value));
                    loadedCount++;
                }
            }

            System.out.println("✅ Successfully loaded " + loadedCount + " variables from .env file");

            // Validate required variables
            validateRequiredVariables(dotenv);

        } catch (DotenvException e) {
            System.err.println("⚠️  Warning: Could not load .env file: " + e.getMessage());
            System.out.println("ℹ️  Using system environment variables instead");
        }
    }

    private static boolean isSensitive(String key) {
        String upperKey = key.toUpperCase();
        return SENSITIVE_KEYS.stream().anyMatch(upperKey::contains);
    }

    private static void validateRequiredVariables(Dotenv dotenv) {
        for (String requiredVar : requiredVars) {
            if (dotenv.get(requiredVar, "").trim().isEmpty()) {
                System.err.println("❌ ERROR: Required environment variable '" + requiredVar + "' is missing or empty");
                System.err.println("💡 Please check your .env file");
            }
        }
    }
}
