package com.moboz.ss3.config.security.filters;

import com.moboz.ss3.config.security.authentication.CustomAuthentication;
import com.moboz.ss3.config.security.managers.CustomAuthenticationManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@AllArgsConstructor
public class CustomAuthenticationFilter extends OncePerRequestFilter { //to be sure the filter runs only its called

    private final CustomAuthenticationManager customAuthenticationManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String key = String.valueOf(request.getHeader("key"));
        CustomAuthentication customAuthentication = new CustomAuthentication(false, key);   //1. create an authentication object which is not yet authenticated

        var authentication = customAuthenticationManager.authenticate(customAuthentication);    //2. delegate the authentication object to the manager
                                                                                                //3. get back the authentication from the manager

        if (authentication.isAuthenticated()) {     //4. if the object is athenticated then send request to the next filter in the chain
            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response); //only when athentication worked
        }


    }
}
