---
title: Hello World
tags:
  - 建站
date: 2017/2/14
---

<s>终于看着教程把这个blog搭好了，可把我累坏了，本来打算建在github上，后来听说建在coding上访问更快，就又搬到了coding上，前前后后用了一下午。

今天是情（nue）人（gou）节，真是不敢出门，建个blog说声“Hello，world！”</s>

现在博客搬运到了Github，之前coding上挂了一次，而且我查ip也没有发现coding使用了国内的服务器。

顺便吐槽一下，Next的动画效果实在有点慢，修改方法也简单，如下（此时版本5.1.0）：
在`YOUR_BLOG\themes\next\source\js\src\motion.js`中找到这段：
```javascript
  NexT.motion.middleWares =  {
    logo: function (integrator) {
      var sequence = [];
      var $brand = $('.brand');
      var $title = $('.site-title');
      var $subtitle = $('.site-subtitle');
      var $logoLineTop = $('.logo-line-before i');
      var $logoLineBottom = $('.logo-line-after i');

      $brand.size() > 0 && sequence.push({
        e: $brand,
        p: {opacity: 1},
        o: {duration: 200}
      });

      NexT.utils.isMist() && hasElement([$logoLineTop, $logoLineBottom]) &&
      sequence.push(
        getMistLineSettings($logoLineTop, '100%'),
        getMistLineSettings($logoLineBottom, '-100%')
      );

      hasElement($title) && sequence.push({
        e: $title,
        p: {opacity: 1, top: 0},
        o: { duration: 200 }
      });

      hasElement($subtitle) && sequence.push({
        e: $subtitle,
        p: {opacity: 1, top: 0},
        o: {duration: 200}
      });

      if (sequence.length > 0) {
        sequence[sequence.length - 1].o.complete = function () {
          integrator.next();
        };
        $.Velocity.RunSequence(sequence);
      } else {
        integrator.next();
      }
```

修改为：

```javascript
  NexT.motion.middleWares =  {
    logo: function (integrator) {
      integrator.next();//here<<<
      var sequence = [];
      var $brand = $('.brand');
      var $title = $('.site-title');
      var $subtitle = $('.site-subtitle');
      var $logoLineTop = $('.logo-line-before i');
      var $logoLineBottom = $('.logo-line-after i');

      $brand.size() > 0 && sequence.push({
        e: $brand,
        p: {opacity: 1},
        o: {duration: 200}
      });

      NexT.utils.isMist() && hasElement([$logoLineTop, $logoLineBottom]) &&
      sequence.push(
        getMistLineSettings($logoLineTop, '100%'),
        getMistLineSettings($logoLineBottom, '-100%')
      );

      hasElement($title) && sequence.push({
        e: $title,
        p: {opacity: 1, top: 0},
        o: { duration: 200 }
      });

      hasElement($subtitle) && sequence.push({
        e: $subtitle,
        p: {opacity: 1, top: 0},
        o: {duration: 200}
      });

      if (sequence.length > 0) {
        sequence[sequence.length - 1].o.complete = function () {
          //integrator.next();
        };
        $.Velocity.RunSequence(sequence);
      } else {
        integrator.next();
      }
```

发现在hexo上用默认的mathjax真tm慢，默认的是`//cdn.mathjax.org/mathjax/latest/MathJax.js`，我先找到一个cdn，换成了`//cdn.bootcss.com/mathjax/2.7.0/MathJax.js`，发现还是很慢，审查元素看一下发现有一处还是访问了cdn.mathjax.org，于是我又换成了`//cdn.bootcss.com/mathjax/2.6.1/MathJax.js`，这下速度正常了，终于省心了。

改的位置在`YOUR_SITE\node_modules\hexo-math\lib\option.js`,搜索cdn.mathjax.org就能找到。