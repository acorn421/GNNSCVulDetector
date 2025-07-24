/*
 * ===== SmartInject Injection Details =====
 * Function      : setTokenDelegation
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup)**: Attacker deploys a malicious token contract that implements the onDelegationSet callback. The contract tracks delegation state and prepares for reentrancy.
 * 
 * **Transaction 2 (Exploitation)**: Attacker calls setTokenDelegation with their malicious token contract. During the external call to onDelegationSet, the malicious contract re-enters setTokenDelegation with different parameters, manipulating the delegation state while the original call is still executing.
 * 
 * **Why Multi-Transaction is Required**:
 * 1. The attacker needs to first deploy and set up the malicious token contract (Transaction 1)
 * 2. The malicious contract needs to track delegation state across calls to determine when to re-enter
 * 3. The exploitation requires the contract to be in a specific state that can only be achieved through prior transactions
 * 4. The vulnerability exploits the persistent state in tokenDlgts mapping that accumulates across multiple transactions
 * 
 * **Exploitation Pattern**:
 * - The external call creates a reentrancy window where tokenDlgts state is inconsistent
 * - An attacker can manipulate delegation chains by re-entering during the callback
 * - The vulnerability depends on the accumulated state from previous delegation calls
 * - Multiple transactions are needed to set up the attack scenario and exploit the state inconsistency
 * 
 * This creates a realistic vulnerability where the external call violates the checks-effects-interactions pattern, allowing state manipulation through reentrancy across multiple transactions.
 */
pragma solidity ^0.4.19;

// DELEGATION SC

// (c) SecureVote 2018

// Released under MIT licence

contract SVDelegation {

    address public owner;

    struct Delegation {
        uint256 thisDelegationId;
        address dlgt;
        uint256 setAtBlock;
        uint256 prevDelegation;
    }

    mapping (address => mapping (address => Delegation)) tokenDlgts;
    mapping (address => Delegation) globalDlgts;

    mapping (uint256 => Delegation) public historicalDelegations;
    uint256 public totalDelegations = 0;

    event SetGlobalDelegation(address voter, address delegate);
    event SetTokenDelegation(address voter, address tokenContract, address delegate);

    constructor() public {
        owner = msg.sender;

        // commit the genesis historical delegation to history (like genesis block)
        createDelegation(address(0), 0);
    }

    function createDelegation(address dlgtAddress, uint256 prevDelegationId) internal returns(Delegation) {
        uint256 myDelegationId = totalDelegations;
        historicalDelegations[myDelegationId] = Delegation(myDelegationId, dlgtAddress, block.number, prevDelegationId);
        totalDelegations += 1;

        return historicalDelegations[myDelegationId];
    }

    // get previous delegation, create new delegation via function and then commit to globalDlgts
    function setGlobalDelegation(address dlgtAddress) public {
        uint256 prevDelegationId = globalDlgts[msg.sender].thisDelegationId;
        globalDlgts[msg.sender] = createDelegation(dlgtAddress, prevDelegationId);
        emit SetGlobalDelegation(msg.sender, dlgtAddress);
    }

    // get previous delegation, create new delegation via function and then commit to tokenDlgts
    function setTokenDelegation(address tokenContract, address dlgtAddress) public {
        uint256 prevDelegationId = tokenDlgts[tokenContract][msg.sender].thisDelegationId;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Check if token contract supports delegation callbacks
        uint256 size;
        assembly { size := extcodesize(tokenContract) }
        if (size > 0) {
            // External call to token contract before state update - VULNERABILITY
            bool success = tokenContract.call(bytes4(keccak256("onDelegationSet(address,address)")), msg.sender, dlgtAddress);
            // Continue regardless of success for backwards compatibility
        }
        
        // State update happens after external call - creates reentrancy window
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        tokenDlgts[tokenContract][msg.sender] = createDelegation(dlgtAddress, prevDelegationId);
        emit SetTokenDelegation(msg.sender, tokenContract, dlgtAddress);
    }

    function resolveDelegation(address voter, address tokenContract) public constant returns(uint256, address, uint256, uint256) {
        Delegation memory _tokenDlgt = tokenDlgts[tokenContract][voter];

        // probs simplest test to check if we have a valid delegation
        if (_tokenDlgt.setAtBlock > 0) {
            return _dlgtRet(_tokenDlgt);
        } else {
            return _dlgtRet(globalDlgts[voter]);
        }
    }

    function _rawGetGlobalDelegation(address _voter) public constant returns(uint256, address, uint256, uint256) {
        return _dlgtRet(globalDlgts[_voter]);
    }

    function _rawGetTokenDelegation(address _voter, address _tokenContract) public constant returns(uint256, address, uint256, uint256) {
        return _dlgtRet(tokenDlgts[_tokenContract][_voter]);
    }

    function _dlgtRet(Delegation d) internal pure returns(uint256, address, uint256, uint256) {
        return (d.thisDelegationId, d.dlgt, d.setAtBlock, d.prevDelegation);
    }
}
