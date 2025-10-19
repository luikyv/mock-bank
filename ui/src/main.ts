import { createApp } from "vue";
import App from "./App.vue";
import router from "./router";
import { createPinia } from "pinia";
import piniaPersist from "pinia-plugin-persistedstate";
import "./assets/main.css";
import { handleError } from "./errors";
import Toast, { POSITION, type PluginOptions } from "vue-toastification";
import "vue-toastification/dist/index.css";

const pinia = createPinia();
pinia.use(piniaPersist);

const options: PluginOptions = {
  position: POSITION.TOP_CENTER,
  timeout: 3000,
  closeOnClick: true,
  pauseOnHover: true,
  draggable: true,
  showCloseButtonOnHover: false,
  hideProgressBar: false,
  icon: true,
  transition: "Vue-Toastification__fade",
};

const app = createApp(App).use(router).use(pinia).use(Toast, options);
app.config.errorHandler = handleError(router);

app.mount("#app");
