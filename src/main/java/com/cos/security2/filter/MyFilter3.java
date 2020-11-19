package com.cos.security2.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        // Token을 만들었다고 가정 : Cos
        // id, pw가 정상적으로 들어와서 로그인이 완료되면, token을 만들어주고 그걸 응답을 해줌
        // 요청할 때 마다 Authorization의 value값으로 token을 가져옴
        // 그때 token이 넘어오면, 이 token이 자신이 내가 만든 token이 맞는지 검증만 하면 됨 (RSA, HS256)
        if(request.getMethod().equals("POST")) {
            System.out.println("POST 요청");
            String headerAuth = request.getHeader("Authorization");
            System.out.println("headerAuth = " + headerAuth);
            System.out.println("Filter3");

            if(headerAuth.equals("Cos")) {
                filterChain.doFilter(request, response);
            } else {
                PrintWriter printWriter = response.getWriter();
                printWriter.println("인증 안됨");
            }
        }
    }
}
