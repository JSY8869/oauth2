package oauth.kakao.security.handler.failure;

import com.fasterxml.jackson.databind.ObjectMapper;
import oauth.kakao.dto.common.ExceptionResponseBody;
import oauth.kakao.util.DefaultHttpMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        setErrorResponse(HttpStatus.FORBIDDEN, response, DefaultHttpMessage.FORBIDDEN, accessDeniedException.getMessage());
    }

    private void setErrorResponse(HttpStatus status, HttpServletResponse response,
                                 String message, String details) throws IOException {

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.toString());
        objectMapper.writeValue(response.getWriter(),
                new ExceptionResponseBody(String.valueOf(status.value()), message, details));
    }
}
