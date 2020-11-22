package com.cos.security2.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.security2.config.auth.PrincipalDetails;
import com.cos.security2.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음
// 원래라면 /login 요청해서 username, password 전송하면 (POST)
// 해당 Filter가 동작을 함 => 그러나 현재 SecurityConfig에 .formLogin().disable() 처리 했으므로 동작을 안함
// 따라서 해당 필터를 따로 만들어서 SecurityConfig에 등록해줘야 함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : attemptAuthentication");

        // 1. username, password 받아서
        // 2. 정상인지 로그인 시도를 해봄 : authenticationManager로 로그인 시도를 하면
        // PrincipalDetailsService가 호출되고 loadUserByUsername() 함수가 실행
        // 3. PrincipalDetails를 세션에 담고 (권한 관리를 위해)
        // 4. JWT 토큰을 만들어서 응답해주면 됨
        try {
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getEmail(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴 됨
            // == DB에 있는 email과 password가 일치한다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // 로그인이 되었다는 뜻
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료");
            System.out.println("principalDetails = " + principalDetails.getUsername());
            System.out.println("principalDetails = " + principalDetails.getPassword());

            // authentication 객체가 session 영역에 되어야 하고, 그 방법이 authentication 객체를 return!
            // return 하는 이유는 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없지만
            // 권한 관리를 시큐리티가 대신 해주기 때문에 편하려고 하는거임!
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행 됨
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨 : 인증이 완료 되었다는 뜻");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        
        // Hash 암호화 방식
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("email", principalDetails.getUser().getEmail())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
    }
}

// 이메일, 패스워드 로그인 정상
// JWT 토큰을 생성
// 클라이언트쪽으로 JWT 토큰을 응답
// 요청할 때 마다 JWT 토큰을 가지고 요청
// 서버는 JWT 토큰이 유효한지를 판단 (이를 위한 필터를 만들어야 함)
