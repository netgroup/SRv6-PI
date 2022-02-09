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
	"io/ioutil"
	"net"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	api "github.com/osrg/gobgp/api"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v2"
)

type SRPolicyNLRI struct {
	Distinguisher uint32
	Color         uint32
	Endpoint      net.IP
}

func (nlri *SRPolicyNLRI) toString() string {
	return fmt.Sprintf("Distinguisher: %d, Color: %d, Endpoint: %s", nlri.Distinguisher, nlri.Color, nlri.Endpoint)
}

func (nlri *SRPolicyNLRI) toNLRI() (srnlri *api.SRPolicyNLRI, err error) {
	return &api.SRPolicyNLRI{
		Length:        192,
		Distinguisher: nlri.Distinguisher,
		Color:         nlri.Color,
		Endpoint:      nlri.Endpoint,
	}, nil
}

type SegmentTypeB struct {
	Sid      net.IP
	Behavior uint8
}

func (seg *SegmentTypeB) toString() string {
	return fmt.Sprintf("Sid: %s, Behavior: %d", seg.Sid, seg.Behavior)
}

func (seg *SegmentTypeB) toBGPSegmentTypeB() (srnlri *api.SegmentTypeB, err error) {
	var epbs = &api.SRv6EndPointBehavior{
		Behavior: api.SRv6Behavior_END_DT4,
	}

	return &api.SegmentTypeB{
		Flags:                     &api.SegmentFlags{SFlag: true},
		Sid:                       seg.Sid,
		EndpointBehaviorStructure: epbs,
	}, nil
}

type SRv6SegmentList struct {
	Weight   uint32
	Segments []*SegmentTypeB
}

func (seglist *SRv6SegmentList) toString() string {
	seglistString := "<"
	for _, seg := range seglist.Segments {
		seglistString += "{ " + seg.toString() + " }"
	}
	seglistString += ">"
	return fmt.Sprintf("Weight: %d\n Segments: %s", seglist.Weight, seglistString)
}

type SRv6PolicyPath struct {
	Nlri        *SRPolicyNLRI
	IsWithdraw  bool
	Age         *timestamppb.Timestamp
	SourceAsn   uint32
	Family      *api.Family
	NeighborIp  string
	SegmentList *SRv6SegmentList
	Bsid        net.IP
	Priority    uint32
	NextHop     net.IP
}

func (p *SRv6PolicyPath) fromFile(filePath string) error {
	yamlFile, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Error reading YAML file: %s\n", err)
		return err
	}
	return yaml.Unmarshal(yamlFile, p)
}

func (p *SRv6PolicyPath) fromPath(path *api.Path) (err error) {
	srnrli := &api.SRPolicyNLRI{}
	tun := &api.TunnelEncapAttribute{}
	subTLVSegList := &api.TunnelEncapSubTLVSRSegmentList{}
	srv6bsid := &api.SRBindingSID{}
	if err = ptypes.UnmarshalAny(path.Nlri, srnrli); err != nil {
		fmt.Println(err)
		return
	}
	p.Nlri = &SRPolicyNLRI{
		Distinguisher: srnrli.Distinguisher,
		Color:         srnrli.Color,
		Endpoint:      net.IP(srnrli.Endpoint),
	}
	p.IsWithdraw = path.IsWithdraw
	p.Age = path.Age
	p.SourceAsn = path.SourceAsn
	p.Family = path.Family
	p.NeighborIp = path.NeighborIp
	p.SegmentList = &SRv6SegmentList{}
	for _, pattr := range path.Pattrs {
		if err := ptypes.UnmarshalAny(pattr, tun); err == nil {
			for _, tlv := range tun.Tlvs {
				for _, innerTlv := range tlv.Tlvs {
					if err := ptypes.UnmarshalAny(innerTlv, subTLVSegList); err == nil {
						p.SegmentList.Weight = subTLVSegList.Weight.Weight
						for _, seglist := range subTLVSegList.Segments {
							segment := &api.SegmentTypeB{}
							if err = ptypes.UnmarshalAny(seglist, segment); err == nil {
								p.SegmentList.Segments = append(p.SegmentList.Segments, &SegmentTypeB{
									Sid:      net.IP(segment.Sid),
									Behavior: uint8(segment.GetEndpointBehaviorStructure().Behavior),
								})
							}
						}
					}
					// search for TunnelEncapSubTLVSRBindingSID
					srbsids := &anypb.Any{}
					if err := ptypes.UnmarshalAny(innerTlv, srbsids); err == nil {
						if err := ptypes.UnmarshalAny(srbsids, srv6bsid); err == nil {
							p.Bsid = net.IP(srv6bsid.Sid)
						}
					}

					// search for TunnelEncapSubTLVSRPriority
					subTLVSRPriority := &api.TunnelEncapSubTLVSRPriority{}
					if err := ptypes.UnmarshalAny(innerTlv, subTLVSRPriority); err == nil {
						p.Priority = subTLVSRPriority.Priority
					}
				}
			}
		}

	}

	return err
}

func (p *SRv6PolicyPath) toPath() (path *api.Path, err error) {
	path = &api.Path{
		IsWithdraw: p.IsWithdraw,
		Age:        p.Age,
		SourceAsn:  p.SourceAsn,
		Family:     p.Family,
		NeighborIp: p.NeighborIp,
		Pattrs:     []*anypb.Any{},
	}

	//
	originAttr, err := ptypes.MarshalAny(&api.OriginAttribute{Origin: 0})
	if err != nil {
		fmt.Println(err)
	}
	path.Pattrs = append(path.Pattrs, originAttr)

	// NextHopAttribute
	nhAttr, err := ptypes.MarshalAny(&api.NextHopAttribute{
		NextHop: p.NextHop.String(),
	})
	if err != nil {
		fmt.Println(err)
	}
	path.Pattrs = append(path.Pattrs, nhAttr)

	bsid, err := ptypes.MarshalAny(&api.SRBindingSID{
		SFlag: true,
		IFlag: false,
		Sid:   p.Bsid,
	})

	if err != nil {
		return nil, err
	}

	tlvbsid, err := ptypes.MarshalAny(&api.TunnelEncapSubTLVSRBindingSID{
		Bsid: bsid,
	})
	if err != nil {
		return nil, err
	}

	seglist := &api.TunnelEncapSubTLVSRSegmentList{
		Weight: &api.SRWeight{
			Flags:  0,
			Weight: 12,
		},
		Segments: []*any.Any{},
	}
	for _, seg := range p.SegmentList.Segments {

		var epbs = &api.SRv6EndPointBehavior{
			Behavior: api.SRv6Behavior(seg.Behavior),
		}
		segment, err := ptypes.MarshalAny(&api.SegmentTypeB{
			Flags:                     &api.SegmentFlags{SFlag: true},
			Sid:                       net.ParseIP(seg.Sid.String()),
			EndpointBehaviorStructure: epbs,
		})
		if err != nil {
			return nil, err
		}
		seglist.Segments = append(seglist.Segments, segment)

	}

	seglistMarshal, err := ptypes.MarshalAny(seglist)

	// TunnelEncapAttribute
	tunnelEncapAttr, err := ptypes.MarshalAny(&api.TunnelEncapAttribute{
		Tlvs: []*api.TunnelEncapTLV{
			{
				Type: 15,
				Tlvs: []*anypb.Any{tlvbsid, seglistMarshal /*, pref, pri */},
			},
		},
	})
	path.Pattrs = append(path.Pattrs, tunnelEncapAttr)

	srnlri, _ := p.Nlri.toNLRI()
	path.Nlri, err = ptypes.MarshalAny(srnlri)
	if err != nil {
		return path, err
	}
	return path, err
}

func (p *SRv6PolicyPath) String() string {
	return fmt.Sprintf("NLRI: %s \nIsWithdraw: %t \nAge: %s \nSourceAsn: %d \nFamily: %s \nNeighborIp: %s \nSegmentList:\n %s \nBsid: %s \nPriority: %d",
		p.Nlri.toString(), p.IsWithdraw, p.Age, p.SourceAsn, p.Family.String(), p.NeighborIp, p.SegmentList.toString(), p.Bsid, p.Priority)
}

func PrintSRv6PolicyPath(path *SRv6PolicyPath) {
	fmt.Println(path.String())
}
