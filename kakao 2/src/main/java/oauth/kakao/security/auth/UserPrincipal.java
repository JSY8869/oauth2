package oauth.kakao.security.auth;

import lombok.Getter;
import lombok.Setter;
import oauth.kakao.entity.User;
import oauth.kakao.entity.RoleType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.List;
import java.util.Map;

@Getter
public class UserPrincipal implements OAuth2User, UserDetails {

    @Setter
    private Map<String, Object> attributes;
    private User user;

    public UserPrincipal(User user) {
        this.user = user;
    }

    public UserPrincipal(User user, Map<String, Object> attributes) {
        this.attributes = attributes;
        this.user = user;
    }

    public Long getId() {
        return user.getId();
    }

    public RoleType getRoleType() {
        return user.getRoleType();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(user.getRoleType().toString()));
    }

    @Override
    public String getPassword() {
        return null;
    }
    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String getName() {
        return user.getName();
    }
}
