package ziponia.spring.security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class ApiController {

    @GetMapping(value = "/api/me")
    public Principal getPrincipal(Principal principal) {
        return principal;
    }

    @GetMapping(value = "/view-token")
    public Boolean viewToken() {
        return true;
    }
}
