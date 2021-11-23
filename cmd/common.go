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
	api "github.com/osrg/gobgp/api"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type SRPolicyNLRI struct {
	Distinguisher uint32
	Color         uint32
	Endpoint      net.IP
}

func (nlri *SRPolicyNLRI) toString() string {
	return fmt.Sprintf("Distinguisher: %d, Color: %d, Endpoint: %s", nlri.Distinguisher, nlri.Color, nlri.Endpoint)
}

type SegmentTypeB struct {
	Sid      net.IP
	Behavior uint8
}

func (seg *SegmentTypeB) toString() string {
	return fmt.Sprintf("Sid: %s, Behavior: %d", seg.Sid, seg.Behavior)
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
	}
	srnlri := &api.SRPolicyNLRI{
		Distinguisher: p.Nlri.Distinguisher,
		Color:         p.Nlri.Color,
		Endpoint:      p.Nlri.Endpoint,
	}
	path.Nlri, err = ptypes.MarshalAny(srnlri)
	if err != nil {
		return nil, err
	}
	return path, err
}

func (p *SRv6PolicyPath) String() string {
	return fmt.Sprintf("NLRI: %s \nIsWithdraw: %t \nAge: %s \nSourceAsn: %d \nFamily: %s \nNeighborIp: %s \nSegmentList:\n %s \nBsid: %s \nPriority: %d",
		p.Nlri.toString(), p.IsWithdraw, p.Age, p.SourceAsn, p.Family.String(), p.NeighborIp, p.SegmentList.toString(), p.Bsid, p.Priority)
}
