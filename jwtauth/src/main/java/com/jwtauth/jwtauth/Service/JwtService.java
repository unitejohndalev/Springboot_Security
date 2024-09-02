
package com.jwtauth.jwtauth.Service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    // a hard-coded secret key used for signing and verifying JWT tokens. It’s
    // important to ensure the security of this key and to consider more secure
    // methods for managing it, such as using environment variables or a dedicated
    // secret management service in a production environment.
    private static final String SECRET_KEY = "A8109E356C606EB46863B1984942F4C4E641CE2D7416855646AEB7860669FC76233ED9FE3C93A25C3874996E6CE6B093407B9E160BD1CF6BF1254983D44969282ADE73535248D19196278AEA5B2C3B070C6802BAF93A3AAFA49CE5D83B1809138A23BF90BA1E28BD9873608AEBAAEE9CDC767BF11C3DDFC5049F14A6227C1B29";

    // This method takes a JWT token as input and extracts the subject (usually the
    // username) from the token’s claims. It uses the `extractClaim` method to
    // extract the subject claim.
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // This is a generic method used to extract a specific claim from the JWT
    // token’s claims. It takes a JWT token and a `Function` that specifies how to
    // extract the desired claim (e.g., subject or expiration) and returns the
    // extracted claim.
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // This method is used to generate a JWT token. It takes a username as input,
    // creates a set of claims (e.g., subject, issued-at, expiration), and then
    // builds a JWT token using the claims and the signing key. The resulting token
    // is returned.
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    // This method is responsible for creating the JWT token. It uses the `Jwts`
    // builder to specify the claims, subject, issue date, expiration date, and the
    // signing key. The token is then signed and compacted to produce the final JWT
    // token, which is returned.
    public String generateToken(Map<String, Object> extractClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // when it expires
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact(); // this will generate and return the token
    }

    // This method is used to validate a JWT token. It first extracts the username
    // from the token and then checks whether it matches the username of the
    // provided `UserDetails` object. Additionally, it verifies whether the token
    // has expired. If the token is valid, it returns `true`; otherwise, it returns
    // `false`.
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    // This method checks whether a JWT token has expired by comparing the token’s
    // expiration date (obtained using `extractExpiration`) to the current date. If
    // the token has expired, it returns `true`; otherwise, it returns `false`.
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // This method extracts the expiration date from the JWT token’s claims. It’s
    // used to determine whether the token has expired or not.
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // This method parses the JWT token and extracts all of its claims. It uses the
    // `Jwts` builder to create a parser that is configured with the appropriate
    // signing key and then extracts the token’s claims.
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // This method is used to obtain the signing key for JWT token creation and
    // validation. It decodes the `SECRET` key, which is typically a Base64-encoded
    // key, and converts it into a cryptographic key using the `Keys.hmacShaKeyFor`
    // method.
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);

    }

}
