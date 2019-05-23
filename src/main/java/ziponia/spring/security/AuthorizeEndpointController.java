package ziponia.spring.security;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.SessionAttributes;

import javax.servlet.http.HttpServletRequest;

@Controller
@SessionAttributes("authorizationRequest")
public class AuthorizeEndpointController {

    @SuppressWarnings("unchecked")
    @GetMapping(value = "/oauth/confirm_access")
    public String authorizeConfirmPage(HttpServletRequest request, Model model) {
//        Map<String, Boolean> scopes = (HashMap<String, Boolean>) request.getAttribute("scopes");
        String[] scopes = request.getAttribute("scope").toString().split(" ");
        model.addAttribute("scopes", scopes);
        return "authorize_confirm";
    }
}
