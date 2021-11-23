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
	"net"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	api "github.com/osrg/gobgp/api"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/anypb"
)

var policiesFile string

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("create called")
		isWithdrawal := false
		attrs := []*any.Any{}
		nlrisr, _ := ptypes.MarshalAny(&api.SRPolicyNLRI{
			Length:        192,
			Distinguisher: 2,
			Color:         99,
			Endpoint:      net.ParseIP("10.0.0.15").To4(),
		})
		originAttr, err := ptypes.MarshalAny(&api.OriginAttribute{Origin: 0})
		if err != nil {
			fmt.Println(err)
		}
		attrs = append(attrs, originAttr)
		nhAttr, err := ptypes.MarshalAny(&api.NextHopAttribute{
			NextHop: "10.0.0.15",
		})
		if err != nil {
			fmt.Println(err)
		}
		attrs = append(attrs, nhAttr)

		sid, err := ptypes.MarshalAny(&api.SRBindingSID{
			SFlag: true,
			IFlag: false,
			Sid:   net.ParseIP("cafe::01"),
		})
		bsid, err := ptypes.MarshalAny(&api.TunnelEncapSubTLVSRBindingSID{
			Bsid: sid,
		})

		var epbs = &api.SRv6EndPointBehavior{
			Behavior: api.SRv6Behavior_END_DT4,
		}
		segment, err := ptypes.MarshalAny(&api.SegmentTypeB{
			Flags:                     &api.SegmentFlags{SFlag: true},
			Sid:                       net.ParseIP("fcff:0:0:20AF::F"),
			EndpointBehaviorStructure: epbs,
		})

		seglist, err := ptypes.MarshalAny(&api.TunnelEncapSubTLVSRSegmentList{
			Weight: &api.SRWeight{
				Flags:  0,
				Weight: 12,
			},
			Segments: []*any.Any{segment},
		})

		pref, err := ptypes.MarshalAny(&api.TunnelEncapSubTLVSRPreference{
			Flags:      0,
			Preference: 11,
		})

		pri, err := ptypes.MarshalAny(&api.TunnelEncapSubTLVSRPriority{
			Priority: 10,
		})

		// Tunnel Encapsulation attribute for SR Policy
		tun, err := ptypes.MarshalAny(&api.TunnelEncapAttribute{
			Tlvs: []*api.TunnelEncapTLV{
				{
					Type: 15,
					Tlvs: []*anypb.Any{bsid, seglist, pref, pri},
				},
			},
		})

		attrs = append(attrs, tun)

		client.AddPath(ctx, &api.AddPathRequest{
			TableType: api.TableType_GLOBAL,
			Path: &api.Path{
				Nlri:       nlrisr,
				IsWithdraw: isWithdrawal,
				Pattrs:     attrs,
				Age:        ptypes.TimestampNow(),
				SourceAsn:  64512,
				Family:     &BgpFamilySRv6IPv6,
			},
		})

		if err != nil {
			fmt.Println(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(createCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	createCmd.PersistentFlags().StringVar(&policiesFile, "policiesFile", "policiesFile.yaml", "policies file (default is ~/policiesFile.yaml)")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// createCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
