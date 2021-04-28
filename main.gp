\\default(parisizemax, 300m)
/**
Copyright 2021 cryptoflop.org
Gestion des changements de mots de passe.
**/
randompwd(len) = {
  externstr(Str("base64 /dev/urandom | head -c ",len))[1];
}
dryrun=1;
sendmail(address,subject,message) = {
  print(message);
  cmd = strprintf("echo %d | mail -s '%s' %s",message,subject,address);
  if(dryrun,print(cmd),system(cmd));
}
template = {
  "Cher collaborateur, votre nouveau mot de passe est %s. "
  "Merci de votre comprehension, le service informatique.";
  }
change_password(user,modulus,e=7) = {
    pwd = randompwd(10);
    chpasswd(user, pwd);
    mail = strprintf(template, pwd);
    m = fromdigits(Vec(Vecsmall(mail)),128);
    c = lift(Mod(m,modulus)^e);
    sendmail(address,"Nouveau mot de passe",c);
    print("[OK] changed password for user ",user);
}




\\ **********************************************************************************
\\  Infos :                                                                         *
\\                                                                                  *
\\    ALGO_USED: Méthode utilisé pour le calcul de dk dans la Décomposition de P.H  *
\\          =1 - La méthode rho de Pollard logarithmique    (Prend bcp de temps)    *
\\          =2 - La méthode Baby-Step Giant-Step log discret (Foireux)              *
\\          =3 - znlog (Interdit...)                                                *
\\                                                                                  *
\\    DEBUG: Put a 1 pour avoir un debug                                            *
\\ **********************************************************************************



\\ **********************************************************************************
\\  Fonctions de l'exercice :                                                       *
\\                                                                                  *
\\    dcd(c): Converti le mot de passe en ASCII en enlevant le padding              *
\\                                                                                  *
\\  But du challenge:                                                               *
\\    retrouver x le mot de passe avec une attaque stéréotypée sur RSA              *
\\    En posant m_ = (m1 + "          "+ m2) et P(y)= (m_ + 128^(#m1)*y)^e - c      *
\\    On a m^e= c mod n <==> f(y) = O mod n                                         *
\\    avec  m = (m1 + x + m2 )                                                      *
\\          m = (m1 + "          "+ m2 ) + 128^(#m1)*x                              *
\\          m = m_ + 128^(#m1)*x                                                    *
\\    Donc on retrouve le mot de passe x en utilisant l'algorithme de Coppersmith   *
\\    qui nous fournit les petites racines < X=128^10 de la fonction f modulo n     *
\\    x appartient à cet ensemble de racines, en l'occurence                        *
\\    on ne trouve qu'une unique, c'est x.                                          *
\\ **********************************************************************************




dcd(c)={
  my(m);
	padding= fromdigits(Vec(Vecsmall("0")), 128); \\ On ajoute le padding
  m=digits(c,128);
  for(i=1, #m, m[i]+= padding);
	Strchr(m);
}



my(m);
[n, e] = readvec("input.txt")[1];
c = readvec("input.txt")[2];
B= 128;
X= 128^10 ;

m= ["Cher collaborateur, votre nouveau mot de passe est ", ". Merci de votre comprehension, le service informatique."];
m1= Vec(Vecsmall(m[1]));
m2= Vec(Vecsmall(m[2]));
m_= concat(m1,Vec(Vecsmall("0000000000")));
m_= concat(m_, m2);
m_= fromdigits(m_, B);

P= Pol( (m_ + 128^(#m2)*y)^e - c, y);
d= poldegree(P);

if( X >= n^(1/e), print("Erreur de message, coppersmith inutilisable"); quit(-1) );
root= zncoppersmith(P, n, X)[1];
x= dcd(root);
  
print( concat(concat( m[1], x), m[2] ) );