package ziponia.spring.security;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.SessionAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@Controller
@SessionAttributes("authorizationRequest")
public class AuthorizeEndpointController {

    @SuppressWarnings("unchecked")
    @GetMapping(value = "/oauth/confirm_access")
    public String authorizeConfirmPage(HttpServletRequest request, Model model) {
        Map<String, Boolean> scopes = (HashMap<String, Boolean>) request.getAttribute("scopes");
        model.addAttribute("scopes", scopes);
        return "authorize_confirm";
    }
}
