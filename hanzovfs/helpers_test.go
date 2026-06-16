package hanzovfs_test

import "github.com/luxfi/age"

type age_Recipient = age.Recipient
func idents(i age.Identity) []age.Identity { return []age.Identity{i} }
func rcpts(r age.Recipient) []age.Recipient { return []age.Recipient{r} }
