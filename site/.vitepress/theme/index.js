import DefaultTheme from 'vitepress/theme';
import SchemaViewer from './components/SchemaViewer.vue';
import './custom.css';

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('SchemaViewer', SchemaViewer);
  },
};
