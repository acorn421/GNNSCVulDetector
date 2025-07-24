/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced stateful, multi-transaction reentrancy vulnerability by adding external call to recipient contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient using `_to.call()` with `onTokenReceived` signature
 * 2. Added code length check to only call contracts (not EOAs)
 * 3. Added require statement for call success to make behavior realistic
 * 4. Positioned external call AFTER balance checks but BEFORE state updates (violating CEI pattern)
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * Transaction 1: Attacker calls transfer() to malicious contract, which records the call but doesn't immediately reenter
 * Transaction 2: Legitimate users perform transfers, changing global balanceOf state
 * Transaction 3: Attacker exploits accumulated state changes through another transfer call that triggers reentrancy
 * The malicious contract can now leverage the changed state from intervening transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - Single transaction reentrancy would fail due to gas limitations and call stack depth
 * - The vulnerability depends on accumulated state changes in balanceOf mapping between transactions
 * - Attacker needs to build up favorable conditions across multiple legitimate transactions
 * - The stateful nature allows attackers to time their exploitation based on contract state evolution
 * - Real-world exploitation requires observing and reacting to state changes from other users' transactions
 * 
 * This creates a realistic, stateful vulnerability where the exploit depends on the contract's evolving state across multiple transactions, making it much more subtle and dangerous than simple single-transaction reentrancy.
 */
pragma solidity ^0.4.25;

contract MYFIE {
    string public name = "Monetize Your Selfie";      //  token name
    string public symbol = "MYFIE";           //  token symbol
    string public version = "2.0";
    uint256 public decimals = 8;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 110000000000000000;
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

    constructor () public {
        MaxSupply = 1154000000000000000;
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
        
        // Stateful reentrancy vulnerability: external call before state updates
        // This creates a window where contract state can be manipulated
        if (isContract(_to)) {
            // Notify recipient contract of incoming transfer
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            require(callSuccess, "Transfer notification failed");
        }
        
        // State changes occur AFTER external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }

    function transferFrom(address src, address dst, uint256 wad) public returns (bool success) {
        require(balanceOf[src] >= wad);
        require(allowance[src][msg.sender] >= wad);
        allowance[src][msg.sender] -= wad;
        balanceOf[src] -= wad;
        balanceOf[dst] += wad;
        emit Transfer(src, dst, wad);
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
