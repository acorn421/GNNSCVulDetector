/*
 * ===== SmartInject Injection Details =====
 * Function      : setTokenDelegation
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
 * Introduced a timestamp-dependent cooldown mechanism that creates a multi-transaction vulnerability. The vulnerability occurs through:
 * 
 * 1. **Timestamp Manipulation**: The function uses block.timestamp for calculating time differences, making it vulnerable to miner timestamp manipulation (miners can adjust timestamps within ~15 minutes).
 * 
 * 2. **Flawed Time Calculation**: The code attempts to convert block numbers to timestamps using a fixed 15-second multiplier (lastDelegationBlock * 15), which is unreliable and creates temporal inconsistencies.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Attacker sets initial delegation, establishing the lastDelegationBlock state
 *    - Transaction 2: Attacker waits for a miner to manipulate timestamps or exploits the flawed block-to-timestamp conversion
 *    - Transaction 3: Attacker bypasses the cooldown by exploiting timestamp inconsistencies to set a new delegation before the intended cooldown period
 * 
 * 4. **Stateful Vulnerability**: The vulnerability persists in the tokenDlgts mapping between transactions, where the setAtBlock value from previous delegations is used for timestamp calculations in future transactions.
 * 
 * 5. **Realistic Attack Vector**: An attacker could coordinate with miners or exploit natural timestamp variations to bypass delegation cooldowns, potentially allowing rapid delegation changes that circumvent intended security controls.
 * 
 * The vulnerability requires multiple transactions because: (1) initial state must be established, (2) timestamp manipulation occurs between blocks, and (3) the exploit leverages the accumulated state from previous transactions.
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
        globalDlgts[msg.sender] = createDelegation(dlgtAddress, prevDelegationId);
        SetGlobalDelegation(msg.sender, dlgtAddress);
    }

    // get previous delegation, create new delegation via function and then commit to tokenDlgts
    function setTokenDelegation(address tokenContract, address dlgtAddress) public {
        uint256 prevDelegationId = tokenDlgts[tokenContract][msg.sender].thisDelegationId;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Add timestamp-based cooldown mechanism that can be manipulated across blocks
        uint256 lastDelegationBlock = tokenDlgts[tokenContract][msg.sender].setAtBlock;
        if (lastDelegationBlock > 0) {
            // Use block.timestamp instead of block.number for time calculations
            // This creates vulnerability to miner timestamp manipulation
            uint256 timeSinceLastDelegation = block.timestamp - (lastDelegationBlock * 15); // Assume 15 sec blocks
            require(timeSinceLastDelegation >= 1 hours, "Delegation cooldown period not met");
        }
        
        // Store current timestamp for future delegation timing validation
        // This creates persistent state that can be exploited across transactions
        tokenDlgts[tokenContract][msg.sender] = createDelegation(dlgtAddress, prevDelegationId);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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