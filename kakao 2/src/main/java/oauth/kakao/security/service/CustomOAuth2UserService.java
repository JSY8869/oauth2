package oauth.kakao.security.service;

import com.nimbusds.oauth2.sdk.util.StringUtils;
import lombok.RequiredArgsConstructor;
import oauth.kakao.dto.OAuth2UserInfo;
import oauth.kakao.dto.OAuth2UserInfoFactory;
import oauth.kakao.entity.AuthProvider;
import oauth.kakao.entity.RoleType;
import oauth.kakao.entity.User;
import oauth.kakao.exception.OAuth2AuthenticationProcessingException;
import oauth.kakao.repository.UserRepository;
import oauth.kakao.security.auth.UserPrincipal;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        try {
            return processOauth2User(userRequest, oAuth2User);
        } catch (OAuth2AuthenticationProcessingException e) {
            /** 수정 필요 **/
            throw new RuntimeException(e);
        }
    }

    private OAuth2User processOauth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) throws OAuth2AuthenticationProcessingException {
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
                userRequest.getClientRegistration().getRegistrationId(),
                oAuth2User.getAttributes()
        );

        if (StringUtils.isBlank(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationProcessingException("empty email");
        }

        Optional<User> userOptional = userRepository.findFirstByEmailOrderByIdAsc(oAuth2UserInfo.getEmail());
        User user;

        if (userOptional.isPresent()) {
            if (!userOptional.get().getAuthProvider().equals(AuthProvider.valueOf(userRequest.getClientRegistration().getRegistrationId()))) {
                throw new OAuth2AuthenticationProcessingException("already sign up other provider");
            }
            user = updateUser(userOptional.get(), oAuth2UserInfo);
        } else {
            user = registerUser(userRequest, oAuth2UserInfo);
        }

        return new UserPrincipal(user, oAuth2User.getAttributes());
    }
    private User registerUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {
        return userRepository.save(User.builder()
                .email("emailTest@naver.com")
                .authProvider(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()))
                .name(oAuth2UserInfo.getName())
                .attributes(oAuth2UserInfo.getAttributes().toString())
                .roleType(RoleType.CLIENT)
                .build());
    }

    private User updateUser(User user, OAuth2UserInfo oAuth2UserInfo) {
        user.update(oAuth2UserInfo.getName(), oAuth2UserInfo.getAttributes());
        return user;
    }
}
