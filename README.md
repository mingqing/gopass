# gopass

Portable Golang password hashing framework

# example

```
package main

import (
    "fmt"
    "github.com/mingqing/gopass"
)

func main() {
    password := "abcd.1234"
    storeHash := "$P$BRf1O1fo.0QP5XOOAuEbY79g82gfKn/"

    p := gopass.NewPasswordHash(8, true)
    k, _ := p.HashPassword(password)

    fmt.Println("plain:", password)
    fmt.Println("hash:", k)

    fmt.Println("check:", k, p.CheckPassword(password, k))
    fmt.Println("check:", storeHash, p.CheckPassword(password, storeHash))
}
```

# refer

[Portable PHP password hashing framework](http://www.openwall.com/phpass/)
