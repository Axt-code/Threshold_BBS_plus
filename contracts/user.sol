// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

contract user {
    // constructor() {
    //     //owner = msg.sender;
    // }

    // modifier onlyOwner() {
    //     require(msg.sender == owner);
    //     _;
    // }

    // mapping(uint256 => G.G2Point) private alpha;

    event SigReqBroadcast(
        address indexed client,
        bytes32 sid,
        bytes32 sigid,
        string message
    );
    // event SigReqReceived(
    //     address indexed party,
    //     address indexed client,
    //     bytes32 sid,
    //     bytes32 sigid,
    //     string message,
    //     uint256[] J
    // );

    event send_msg(uint256 iddd);

    function broadcastSigReq(
        bytes32 sid,
        bytes32 sigid,
        string calldata message
    ) external {
        emit SigReqBroadcast(msg.sender, sid, sigid, message);
    }

    function sample(uint256 sid) external {
        emit send_msg(sid);
    }

    // function sample(uint id) public {
    //     emit send_msg(id);
    // }
    // function receiveSigReq(
    //     address client,
    //     bytes32 sid,
    //     bytes32 sigid,
    //     string calldata message,
    //     uint256[] calldata J
    // ) external {
    //     emit SigReqReceived(msg.sender, client, sid, sigid, message, J);
    // }
}
