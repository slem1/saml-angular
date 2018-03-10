import {Component, OnInit} from '@angular/core';
import {HttpClient} from "@angular/common/http";

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {

  title = 'app';

  constructor(private httpClient: HttpClient){}

  ngOnInit(): void {

    this.httpClient.get('/service/auth/token').subscribe(r => console.log(r));

  }

}
