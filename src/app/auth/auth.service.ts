import { Injectable } from '@angular/core'
import decode from 'jwt-decode'
import { BehaviorSubject, Observable, pipe, throwError } from 'rxjs'
import { catchError, filter, map, mergeMap, tap } from 'rxjs/operators'

import { Role } from '../auth/auth.enum'
import { CacheService } from '../auth/cache.service'
import { transformError } from '../common/common'
import { IUser, User } from '../user/user/user'

/*
*IAuthStatus interface to store decoded user information, a helper interface,
 and the secure by default defaultAuthStatus
*/

export interface IAuthStatus {
  isAuthenticated: boolean
  userRole: Role
  userId: string
}

export interface IServerAuthResponse {
  accessToken: string
}

export const defaultAuthStatus: IAuthStatus = {
  isAuthenticated: false,
  userRole: Role.None,
  userId: '',
}

export interface IAuthService {
  readonly authStatus$: BehaviorSubject<IAuthStatus>
  readonly currentUser$: BehaviorSubject<IUser>
  login(email: string, password: string): Observable<void>
  logout(clearToken?: boolean): void
  getToken(): string
}

@Injectable()
export abstract class AuthService extends CacheService implements IAuthService {
  readonly authStatus$ = new BehaviorSubject<IAuthStatus>(defaultAuthStatus)
  readonly currentUser$ = new BehaviorSubject<IUser>(new User())

  private getAndUpdateUserIfAuthenticated = pipe(
    filter((status: IAuthStatus) => status.isAuthenticated),
    mergeMap(() => this.getCurrentUser()),
    map((user: IUser) => {
      this.currentUser$.next(user)
      console.log('getAndUpdateUserIfAuthenticated: current user ', this.currentUser$)
    }),
    catchError(transformError)
  )

  protected readonly resumeCurrentUser$ = this.authStatus$.pipe(
    this.getAndUpdateUserIfAuthenticated
  )

  constructor() {
    super()
    if (this.hasExpiredToken()) {
      this.logout(true)
    } else {
      this.authStatus$.next(this.getAuthStatusFromToken())
      // To load user on browser refresh,
      // resume pipeline must activate on the next cycle
      // Which allows for all services to constructed properly
      setTimeout(() => this.resumeCurrentUser$.subscribe(), 0)
    }
  }

  /** Implementando principio open/close abierto  para extender cerrado para modificar */
  /** Las tres funciones que siguen son las que se implementan en los proveedores */
  protected abstract authProvider(
    email: string,
    password: string
  ): Observable<IServerAuthResponse>
  protected abstract transformJwtToken(token: unknown): IAuthStatus
  protected abstract getCurrentUser(): Observable<User>

  /** Los siguientes 3 metodos usan los metodos anteriores que se implementan
   * en los diferentes providers para poder autenticar.
   */

  /**
   * Se implementa el metodo login el cual tiene la logica estandar para auntenticar
   * usando el metodo authProvider
   * @param email correo.
   * @param password password.
   */
  login(email: string, password: string): Observable<void> {
    this.clearToken()
    const loginResponse$ = this.authProvider(email, password).pipe(
      map((value) => {
        this.setToken(value.accessToken)
        console.log('access login ' + value.accessToken)
        const token = decode(value.accessToken)
        console.log('token login', token)
        return this.transformJwtToken(token)
      }),
      tap((status) => this.authStatus$.next(status)),
      /*filter((status: IAuthStatus) => status.isAuthenticated),
      mergeMap(() => this.getCurrentUser()),
      map((user) => this.currentUser$.next(user)),
      catchError(transformError)*/
      this.getAndUpdateUserIfAuthenticated
    )
    loginResponse$.subscribe({
      error: (err) => {
        this.logout()
        return throwError(err)
      },
    })
    return loginResponse$
  }

  /**
   * el metodo logout que se desconecta de la aplicacion.
   * @param clearToken false o true opcional.
   */
  logout(clearToken?: boolean): void {
    if (clearToken) {
      // limpia el token del localStorage
      this.clearToken()
    }
    setTimeout(() => this.authStatus$.next(defaultAuthStatus), 0)
  }

  /**
   * Obtiene el token del localStorage.
   */
  getToken(): string {
    return this.getItem('jwt') ?? ''
  }

  /**
   * actualizar la informacion el localStorage.
   * @param jwt token.
   */
  protected setToken(jwt: string) {
    this.setItem('jwt', jwt)
  }

  /**
   * Limpiar token en el localStorage.
   */
  protected clearToken() {
    this.removeItem('jwt')
  }

  /**
   * Valida si el token ha expirado.
   */
  protected hasExpiredToken(): boolean {
    const jwt = this.getToken()
    if (jwt) {
      const payload = decode(jwt) as any
      return Date.now() >= payload.exp * 1000
    }
    return true
  }

  /**
   * Obtienen el status desde el token.
   */
  protected getAuthStatusFromToken(): IAuthStatus {
    console.log('token getAuthStatusFromToken')
    console.log('Token getAuthStatusFromToken ' + this.getToken())
    console.log(decode(this.getToken()))
    return this.transformJwtToken(decode(this.getToken()))
  }
}
