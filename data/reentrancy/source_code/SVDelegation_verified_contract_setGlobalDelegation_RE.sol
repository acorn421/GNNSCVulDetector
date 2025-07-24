/*
 * ===== SmartInject Injection Details =====
 * Function      : setGlobalDelegation
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the delegate address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `dlgtAddress.call()` before updating `globalDlgts[msg.sender]`
 * 2. The call invokes `onDelegationPending()` method on the delegate contract
 * 3. State modifications occur after the external call, violating the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `setGlobalDelegation(maliciousContract)` with a contract that implements `onDelegationPending()`
 * 2. **During callback**: The malicious contract can re-enter `setGlobalDelegation()` but cannot yet fully exploit due to state not being finalized
 * 3. **Transaction 2**: Attacker leverages the modified delegation state created in Transaction 1 to perform additional exploitation
 * 4. **Accumulated State**: Each call modifies `totalDelegations` counter and historical delegations, creating opportunities for state-dependent attacks
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability exploits the persistent state changes in `globalDlgts` mapping and `totalDelegations` counter
 * - The delegation system's historical tracking creates state dependencies between calls
 * - An attacker needs to first establish a malicious delegate, then leverage that established state in subsequent transactions
 * - The reentrancy during the callback can read current state but the full exploitation requires the state changes to be committed and used in later transactions
 * 
 * **Realistic Integration**: The delegate notification is a reasonable feature that could exist in production code for delegation systems, making this vulnerability subtle and realistic.
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

    function SVDelegation() public {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify delegate of pending delegation (external call before state update)
        if (dlgtAddress != address(0)) {
            bool success = dlgtAddress.call(
                bytes4(keccak256("onDelegationPending(address,uint256)")), 
                msg.sender, 
                prevDelegationId
            );
            require(success, "Delegate notification failed");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        globalDlgts[msg.sender] = createDelegation(dlgtAddress, prevDelegationId);
        SetGlobalDelegation(msg.sender, dlgtAddress);
    }

    // get previous delegation, create new delegation via function and then commit to tokenDlgts
    function setTokenDelegation(address tokenContract, address dlgtAddress) public {
        uint256 prevDelegationId = tokenDlgts[tokenContract][msg.sender].thisDelegationId;
        tokenDlgts[tokenContract][msg.sender] = createDelegation(dlgtAddress, prevDelegationId);
        SetTokenDelegation(msg.sender, tokenContract, dlgtAddress);
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