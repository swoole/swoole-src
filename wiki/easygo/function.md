easygo函数列表
=====

跳转到新地址
```go
func (c Controller) Redirect(url string) 
```
传递数据给模板引擎 
```go
func (c Controller) Assign(name string, data interface{})  
```
 渲染模板  
```go
func (c Controller) Render(tpl_file string)
```
输出html内容 
```go 
func (c Controller) Echo(html string) 
```
将数据json串化并输出   
```go
func (c Controller) EchoJson(data interface{}) 
```
