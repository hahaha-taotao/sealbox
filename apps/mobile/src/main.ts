import { createApp } from "vue";
import App from "./App.vue";
import "./styles.css";

if (/Android/i.test(navigator.userAgent)) {
  document.documentElement.classList.add("is-android");
}

createApp(App).mount("#app");
