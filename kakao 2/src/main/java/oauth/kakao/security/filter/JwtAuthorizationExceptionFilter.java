package oauth.kakao.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import oauth.kakao.dto.common.ExceptionResponseBody;
import oauth.kakao.util.DefaultHttpMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.security.sasl.AuthenticationException;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class JwtAuthorizationExceptionFilter extends OncePerRequestFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (ExpiredJwtException e) {
            setErrorResponse(
                    HttpStatus.MOVED_PERMANENTLY,
                    response,
                    String.format(DefaultHttpMessage.MOVED_PERMANENTLY, "/login"),
                    e.getMessage());
        } catch (JwtException | AuthenticationException e) {
            setErrorResponse(HttpStatus.UNAUTHORIZED, response, DefaultHttpMessage.UNAUTHORIZED, e.getMessage());
        } catch (IllegalArgumentException | AccessDeniedException e) {
            setErrorResponse(HttpStatus.BAD_REQUEST, response, DefaultHttpMessage.BAD_REQUEST, e.getMessage());
        } catch (Exception e) {
            setErrorResponse(
                    HttpStatus.INTERNAL_SERVER_ERROR, response, DefaultHttpMessage.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    public void setErrorResponse(HttpStatus status, HttpServletResponse response, String message, String details) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.toString());
        objectMapper.writeValue(response.getWriter(),
                new ExceptionResponseBody(String.valueOf(status.value()), message, details));
    }
}
