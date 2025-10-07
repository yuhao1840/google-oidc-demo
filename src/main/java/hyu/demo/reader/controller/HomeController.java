package hyu.demo.reader.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home(@AuthenticationPrincipal OidcUser principal, Model model) {
        // If user is already authenticated, we could redirect to dashboard
        // But we'll let the template handle it for better UX
        if (principal != null) {
            // Add user info to model for the index page
            model.addAttribute("userName", principal.getFullName());
            model.addAttribute("userEmail", principal.getEmail());
        }
        return "index";
    }

    @GetMapping("/login")
    public String login(@AuthenticationPrincipal OidcUser principal) {
        // If already logged in, redirect to dashboard
        if (principal != null) {
            return "redirect:/dashboard";
        }
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model, @AuthenticationPrincipal OidcUser principal) {
        // If not authenticated, redirect to login
        if (principal == null) {
            return "redirect:/login";
        }

        // Basic user info
        model.addAttribute("name", principal.getFullName());
        model.addAttribute("email", principal.getEmail());
        model.addAttribute("picture", principal.getPicture());
        model.addAttribute("subject", principal.getSubject());
        model.addAttribute("issuer", principal.getIssuer());

        // Detect provider
        String provider = detectProvider(principal.getIssuer().toString());
        model.addAttribute("provider", provider);

        // JWT Token information
        String idToken = principal.getIdToken().getTokenValue();
        model.addAttribute("idToken", idToken);

        // Format timestamps
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
                .withZone(ZoneId.systemDefault());

        model.addAttribute("tokenIssuedAt", formatter.format(principal.getIdToken().getIssuedAt()));
        model.addAttribute("tokenExpiresAt", formatter.format(principal.getIdToken().getExpiresAt()));
        model.addAttribute("tokenAuthorizedParty", principal.getIdToken().getAuthorizedParty());

        // All claims
        Map<String, Object> claims = principal.getClaims();
        model.addAttribute("claims", claims);

        return "dashboard";
    }

    private String detectProvider(String issuer) {
        if (issuer.contains("google")) {
            return "Google";
        } else if (issuer.contains("auth0")) {
            return "Auth0";
        } else if (issuer.contains("okta")) {
            return "Okta";
        } else if (issuer.contains("keycloak")) {
            return "Keycloak";
        } else {
            return "OIDC Provider";
        }
    }
}