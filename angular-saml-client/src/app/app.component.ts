import {Component, OnInit} from '@angular/core';
import {HttpClient} from "@angular/common/http";
import {HttpErrorResponse, HttpResponse} from "@angular/common/http/src/response";
import {ApiToken} from "./ApiToken";

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {

  title = 'app';

  constructor(private httpClient: HttpClient) {
  }

  ngOnInit(): void {

    this.httpClient.get('/service/auth/token')
      .subscribe(
          r => console.log(r),
          error => this.handleTokenError(error));

  }


  handleTokenSuccess(response: HttpResponse<ApiToken>){
    console.log(response.body);
    localStorage.setItem("apiToken", response.body.token);
  }

  handleTokenError(error: HttpErrorResponse) {

    if(error.status === 401){
      window.location.replace('http://localhost:8080/saml/login')
    }

  }


}
