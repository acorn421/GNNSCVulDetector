/*
 * ===== SmartInject Injection Details =====
 * Function      : setGlobalDelegation
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through time-based delegation cooldown and authority weighting. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup):** Attacker sets an initial delegation, which stores the timestamp in state (setAtBlock field in the delegation struct).
 * 
 * **Transaction 2 (Exploitation):** Attacker or miner manipulates block.timestamp to bypass the cooldown period or gain favorable authority weighting. The vulnerability manifests in two ways:
 * 
 * 1. **Cooldown Bypass:** If lastDelegationTime is retrieved from previous state, miners can manipulate block.timestamp to make the cooldown check pass prematurely (block.timestamp > lastDelegationTime + 300).
 * 
 * 2. **Authority Manipulation:** The timestamp comparison (block.timestamp - newDelegation.setAtBlock < 3600) can be manipulated by miners to artificially grant "recent delegation" status to older delegations.
 * 
 * **Multi-Transaction Requirement:** The vulnerability requires state persistence between transactions - the first transaction must establish the baseline timestamp in state, then subsequent transactions can exploit the timestamp manipulation. This creates a realistic attack scenario where miners can coordinate timestamp manipulation across multiple blocks to gain unauthorized delegation privileges or bypass security restrictions.
 * 
 * The vulnerability is subtle because it appears to implement legitimate time-based security measures, but the reliance on manipulable block.timestamp creates exploitation opportunities that accumulate across multiple transactions.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based delegation cooldown to prevent spam
        uint256 lastDelegationTime = globalDlgts[msg.sender].setAtBlock;
        if (lastDelegationTime > 0) {
            require(block.timestamp > lastDelegationTime + 300, "Delegation cooldown period not met");
        }
        
        // Create new delegation with timestamp-based priority weighting
        Delegation memory newDelegation = createDelegation(dlgtAddress, prevDelegationId);
        
        // Apply timestamp-based authority weighting for recent delegations
        if (block.timestamp - newDelegation.setAtBlock < 3600) {
            // Recent delegations get higher authority weight stored in state
            globalDlgts[msg.sender] = newDelegation;
        } else {
            // Older delegations maintain standard authority
            globalDlgts[msg.sender] = newDelegation;
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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