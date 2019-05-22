package ziponia.spring.security;

import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.transaction.annotation.Transactional;

@Log
public class ClientDetailsServiceImpl implements ClientDetailsService {

    @Autowired
    private OAuth2ClientRepository oAuth2ClientRepository;

    @Override
    @Transactional
    public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        ClientEntity clientEntity = oAuth2ClientRepository.findByClientId(clientId);
        return new BaseClientDetails(clientEntity);
    }
}
