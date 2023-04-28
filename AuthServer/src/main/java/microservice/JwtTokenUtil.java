package microservice;

import java.security.*;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtTokenUtil {

    private static final long serialVersionUID = -2550185165626007488L;
    // Validity for 5 hours.
    public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;
    private final PrivateKey privateKey;

    public JwtTokenUtil(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    // Retrieve expiration date from jwt token.
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    // Retrieve claims from token.
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    // For retrieving any information from token we will need the secret key.
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(privateKey).parseClaimsJws(token).getBody();
    }

    // Check if the token has expired.
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }


    // Generate a token.
    public String generateToken(Map<String, Object> claims, String subject) {

        return Jwts.builder()
                .setClaims(claims)
                .setIssuer("auth@istio")
                .setAudience("ingress gateway")
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }
}
