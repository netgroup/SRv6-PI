/*
Copyright © 2021 Francesco Lombardo <franclombardo@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"

	api "github.com/osrg/gobgp/api"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all SRv6 Policy Path",
	Long:  `List all SRv6 Policy Path`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("SRv6 Policy List")
		paths, err := client.ListPath(ctx, &api.ListPathRequest{
			TableType: api.TableType_GLOBAL,
			Family:    &BgpFamilySRv6IPv6,
		})
		if err != nil {
			fmt.Println(err)
		}
		listPaths, err := paths.Recv()
		if err != nil {
			fmt.Println(err)
		}
		if listPaths == nil || (len(listPaths.Destination.Paths) == 0) {
			fmt.Println("No path found")
		} else {
			fmt.Printf("Paths: (%d available)\n", len(listPaths.Destination.Paths))
			for i, path := range listPaths.Destination.Paths {
				policyPath := SRv6PolicyPath{}
				policyPath.fromPath(path)
				fmt.Printf("Path #%d:\n%s\n", i, policyPath.String())
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(listCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// listCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
