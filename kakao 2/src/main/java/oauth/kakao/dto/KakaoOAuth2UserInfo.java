package oauth.kakao.dto;

import java.util.Map;

public class KakaoOAuth2UserInfo extends OAuth2UserInfo{

    private Long id;

    public KakaoOAuth2UserInfo(Map<String, Object> attributes) {
        super((Map<String, Object>) attributes.get("kakao_account"));
        this.id = (Long) attributes.get("id");
    }

    @Override
    public String getId() {
        return this.id.toString();
    }

    @Override
    public String getEmail() {
        //Todo 이메일 권한 받으면 수정 예정
        return "emailTest@naver.com";
    }

    @Override
    public String getName() {
        return (String) ((Map<String, Object>) attributes.get("profile")).get("nickname");
    }


}
