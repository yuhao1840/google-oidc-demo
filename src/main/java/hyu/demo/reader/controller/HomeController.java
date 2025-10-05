package hyu.demo.reader.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "index";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model, @AuthenticationPrincipal OidcUser principal) {
        if (principal != null) {
            // Basic user info
            model.addAttribute("name", principal.getFullName());
            model.addAttribute("email", principal.getEmail());
            model.addAttribute("picture", principal.getPicture());
            model.addAttribute("subject", principal.getSubject());
            model.addAttribute("issuer", principal.getIssuer());

            // JWT Token information
            String idToken = principal.getIdToken().getTokenValue();
            model.addAttribute("idToken", idToken);
            model.addAttribute("idTokenShort", maskToken(idToken, 10));

            // Token metadata - FIXED: Convert Instant to formatted string
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                    .withZone(ZoneId.systemDefault());

            Instant issuedAt = principal.getIdToken().getIssuedAt();
            Instant expiresAt = principal.getIdToken().getExpiresAt();

            model.addAttribute("tokenIssuedAt", formatter.format(issuedAt));
            model.addAttribute("tokenExpiresAt", formatter.format(expiresAt));
            model.addAttribute("tokenAuthorizedParty", principal.getIdToken().getAuthorizedParty());

            // Token header and payload (for educational purposes)
            String[] tokenParts = idToken.split("\\.");
            if (tokenParts.length >= 2) {
                model.addAttribute("tokenHeader", decodeTokenPart(tokenParts[0]));
                model.addAttribute("tokenPayload", decodeTokenPart(tokenParts[1]));
            }

            // All claims
            Map<String, Object> claims = principal.getClaims();
            model.addAttribute("claims", claims);

            // Token type and algorithm (from header)
            if (claims.containsKey("alg")) {
                model.addAttribute("tokenAlgorithm", claims.get("alg"));
            }
        }
        return "dashboard";
    }

    private String maskToken(String token, int visibleChars) {
        if (token == null || token.length() <= visibleChars * 2) {
            return "***";
        }
        return token.substring(0, visibleChars) + "..." + token.substring(token.length() - visibleChars);
    }

    private String decodeTokenPart(String encoded) {
        try {
            byte[] decodedBytes = java.util.Base64.getUrlDecoder().decode(encoded);
            return new String(decodedBytes);
        } catch (Exception e) {
            return "Unable to decode: " + e.getMessage();
        }
    }
}