package com.jisu.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();//모든 곳에 인증해야함
        http
                .formLogin()
//                .loginPage("/loginPage")        //로그인커스텀 페이지 기본은 security가 제공하는 /login으로 이동한다.
                .defaultSuccessUrl("/")          //성공했을때의 이동 페이지
                .failureUrl("/login")  //실패시 돌아갈 URL
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")  //로그인읋 할때 전송되는 URL
                .successHandler(new AuthenticationSuccessHandler() { //익명 클래스 성공했을때의 호출하는 핸들러
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        //Authentication인증 정보가 담긴 객체
                        System.out.println("Authentication: " + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception: " + exception.getMessage());
                        response.sendRedirect("loginPage");
                    }
                })
                .permitAll()//위에는 모든사람이 접근 허용
        ;
        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login") //이동할 페이지만
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession httpSession = request.getSession();
                        httpSession.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {//logoutSuccessUrl와 비슷하지만 구현할수있는게 많음
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me")        //로그인유지하기 쿠키이름 설정해주면됨.
        ;
    }
}
