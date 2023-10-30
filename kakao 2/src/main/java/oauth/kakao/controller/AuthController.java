package oauth.kakao.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {

    @GetMapping("auth/token")
    public String token(@RequestParam String error, @RequestHeader(name = "AccessToken") String accessToken, @RequestHeader(name = "RefreshToken") String refreshToken) {
        System.out.println("accessToken = " + accessToken);
        System.out.println("refreshToken = " + refreshToken);
        return error;
    }

    @GetMapping("test")
    public String test() {
        return "ok";
    }
}
