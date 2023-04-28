pragma solidity ^0.8.0;

contract RevokedDIDs {
    mapping(string => bool) private revokedDIDs;
    address private owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the contract owner can call this function.");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function revokeDID(string memory did) public onlyOwner {
        revokedDIDs[did] = true;
    }

    function isRevoked(string memory did) public view returns (bool) {
        return revokedDIDs[did];
    }
}
