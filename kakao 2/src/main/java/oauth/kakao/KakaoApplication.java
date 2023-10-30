package oauth.kakao;

import oauth.kakao.config.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class KakaoApplication {

	public static void main(String[] args) {
		SpringApplication.run(KakaoApplication.class, args);
	}

}
