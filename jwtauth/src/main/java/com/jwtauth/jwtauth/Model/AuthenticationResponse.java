

package com.jwtauth.jwtauth.Model ;

import lombok.AllArgsConstructor ;
import lombok.Builder ;
import lombok.Data ;
import lombok.NoArgsConstructor ;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {

    private String token;
}
