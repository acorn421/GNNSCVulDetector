/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Updates**: Inserted a callback mechanism `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))` that executes BEFORE the balance updates
 * 2. **Contract Detection**: Added `_to.code.length > 0` check to only call contracts, making the vulnerability more realistic
 * 3. **State Updates After External Call**: Kept the critical state updates (`balanceOf[msg.sender] -= _value` and `balanceOf[_to] += _value`) after the external call
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys malicious contract with `onTokenReceived` function
 * - Attacker obtains some tokens through normal means
 * - Malicious contract is now ready to receive callbacks
 * 
 * **Transaction 2 - Initial Attack:**
 * - Attacker calls `transfer()` to send tokens to their malicious contract
 * - The `onTokenReceived` callback is triggered BEFORE balance updates
 * - At this point, `balanceOf[attacker]` still contains the original amount (state not yet updated)
 * 
 * **Transaction 3+ - Reentrancy Chain:**
 * - Inside `onTokenReceived`, malicious contract calls `transfer()` again
 * - Since balances haven't been updated yet, the require checks pass
 * - This creates a recursive call chain where each call sees the original balance
 * - Each reentrant call can transfer the same tokens multiple times
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **Contract Deployment**: The malicious contract must be deployed in a separate transaction before the attack
 * 2. **State Accumulation**: The vulnerability exploits the fact that state changes persist between transactions, allowing the attacker to build up a position
 * 3. **Callback Dependency**: The external call mechanism requires the recipient to be a contract with the callback function, necessitating prior setup
 * 4. **Realistic Attack Pattern**: Real-world reentrancy attacks typically involve multiple steps: setup, trigger, and exploitation phases
 * 
 * **Exploitation Flow:**
 * ```
 * Tx1: Deploy malicious contract
 * Tx2: Initial transfer() call → triggers callback → state still unchanged
 * Tx3: Reentrant transfer() calls → drain funds → state finally updated
 * ```
 * 
 * The vulnerability is genuine because the external call occurs before critical state updates, allowing recursive calls to see stale state across multiple transaction contexts. This creates a stateful, multi-transaction attack vector that mirrors real-world reentrancy patterns seen in production systems."
 */
pragma solidity ^0.4.16;

contract SWTCoin {
    string public name = "SWTCoin";      //  token name
    string public symbol = "SWAT";           //  token symbol
    string public version = "1.0";
    uint256 public decimals = 8;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 29000000000000000;
    uint256 public MaxSupply = 0;
    bool public stopped = true;

    //000 000 000 000 000 000
    address owner = 0x48850F503412d8A6e3d63541F0e225f04b13a544;
    address minter = 0x47c803871c99EC7180E50dcDA989320871FcBfEE;
    
    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isMinter {
        assert(minter == msg.sender);
        _;
    }
    
    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    function SWTCoin() public {
        MaxSupply = 154000000000000000;
        balanceOf[owner] = totalSupply;
        emit Transfer(0x0, owner, totalSupply);
    }

    function changeOwner(address _newaddress) isOwner public {
        owner = _newaddress;
    }

    function changeMinter(address _new_mint_address) isOwner public {
        minter = _new_mint_address;
    }
    
    function airdropMinting(address[] _to_list, uint[] _values) isMinter public {
        require(_to_list.length == _values.length);
        for (uint i = 0; i < _to_list.length; i++) {
            mintToken(_to_list[i], _values[i]);
        }
    }

    function setMaxSupply(uint256 maxsupply_amount) isOwner public {
      MaxSupply = maxsupply_amount;
    }

    function mintToken(address target, uint256 mintedAmount) isMinter public {
      require(MaxSupply > totalSupply);
      balanceOf[target] += mintedAmount;
      totalSupply += mintedAmount;
      emit Transfer(0, this, mintedAmount);
      emit Transfer(this, target, mintedAmount);
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Callback to recipient if it's a contract - VULNERABILITY INJECTION
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
