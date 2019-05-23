package ziponia.spring.security;

import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@RestController
public class ApiController {

    @GetMapping(value = "/api/me")
    public Principal getPrincipal(Principal principal) {
        return principal;
    }

    @GetMapping(value = "/api/private")
    public Map<String, String> privateApi() {
        Map<String, String> model = new HashMap<>();
        model.put("name", "jihoon");
        model.put("nick", "zef");
        return model;
    }

    @GetMapping(value = "/api/private/token")
    public OAuth2Authentication privateToken(OAuth2Authentication authentication) {
        return authentication;
    }


    @GetMapping(value = "/view-token")
    public Boolean viewToken() {
        return true;
    }
}
