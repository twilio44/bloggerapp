package com.blog.security;

import com.blog.exception.BlogAPIException;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtTokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwt-ExpirationMs-milliseconds}")
    private int jwtExpirationlnMs;

    // generate token
    public String generateToken(Authentication authentication) {
        // generateToken method is called from AuthController Signin feature

        String username = authentication.getName();

        Date currentDate = new Date();
        Date expireDate = new Date(currentDate.getTime() + jwtExpirationlnMs);

        String token = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(expireDate)
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
        return token;
    }

    // get username from the token
    public String getUsernameFromJWT(String token) {

        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }


    // validate JWT token
    public boolean validateToken(String token) throws BlogAPIException {
        // here we have validateToken(String token) method and
        // this Token is actually applying the secret key again:
        // And after applying the secret key  it validates the Token
        // Because to validate the Token  only when secret key is applied  I can extract the
        // information from the Token  that’s why we are again applying the secret key here:
        //
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (SignatureException ex) {
            // Handle any exceptions
            throw new BlogAPIException(HttpStatus.BAD_REQUEST, "Invalid JWT signature");

        } catch (MalformedJwtException ex) {

            throw new BlogAPIException(HttpStatus.BAD_REQUEST, "Invalid JWT token");

        } catch (ExpiredJwtException ex) {

            throw new BlogAPIException(HttpStatus.BAD_REQUEST, "Expired JWT token");
        } catch (UnsupportedJwtException ex) {

            throw new BlogAPIException(HttpStatus.BAD_REQUEST, "Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            // Handle any exceptions
            throw new BlogAPIException(HttpStatus.BAD_REQUEST, "JWT claims string is empty.");
        }

    }
//    This is for finding Epiry time --> rest of the part in JwtAuhenticationFilter
//    public long getRemainingTimeInMillis(String token) {
//        Claims claims = Jwts.parser()
//                .setSigningKey(jwtSecret)
//                .parseClaimsJws(token)
//                .getBody();
//        Date expirationDate = claims.getExpiration();
//        long currentMillis = System.currentTimeMillis();
//        long expirationMillis = expirationDate.getTime();
//        return expirationMillis - currentMillis;
//    }
}


