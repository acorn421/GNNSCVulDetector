/*
 * ===== SmartInject Injection Details =====
 * Function      : Withdraw
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing time-based withdrawal limits that rely on block.timestamp for critical security logic. The vulnerability requires multiple transactions across different time periods to exploit, as the daily withdrawal limit reset depends on timestamp calculations that can be manipulated by miners. State variables (lastWithdrawalTime and dailyWithdrawnAmount) persist between transactions, creating conditions where sequential withdrawals can bypass intended limits through timestamp manipulation. The cooldown period and daily limit calculations using block.timestamp division create exploitable timing windows that require coordinated multi-transaction attacks across different blocks/time periods.
 */
pragma solidity ^0.4.18;

contract usingOwnership {
  address public contract_owner;

  modifier onlyOwner() {
    require(msg.sender == contract_owner);
    _;
  }

  function usingOwnership() internal {
    contract_owner = msg.sender;
  }

  // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint) public lastWithdrawalTime;
  mapping(address => uint) public dailyWithdrawnAmount;
  uint public dailyWithdrawalLimit = 1 ether;
  uint public withdrawalCooldown = 1 hours;
  
  function Withdraw(uint _amount) onlyOwner public {
    // Check cooldown period using block.timestamp
    require(block.timestamp >= lastWithdrawalTime[msg.sender] + withdrawalCooldown, "Cooldown period not met");
    
    // Reset daily limit if new day (vulnerable timestamp calculation)
    if (block.timestamp / 1 days > lastWithdrawalTime[msg.sender] / 1 days) {
      dailyWithdrawnAmount[msg.sender] = 0;
    }
    
    // Check daily withdrawal limit
    require(dailyWithdrawnAmount[msg.sender] + _amount <= dailyWithdrawalLimit, "Daily withdrawal limit exceeded");
    
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    if (_amount > this.balance)
      _amount = this.balance;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Update state with current timestamp
    lastWithdrawalTime[msg.sender] = block.timestamp;
    dailyWithdrawnAmount[msg.sender] += _amount;
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    contract_owner.transfer(_amount);
  }

  function TransferOwnership(address _new_owner) onlyOwner public {
    require(_new_owner != address(0));
    contract_owner = _new_owner;
  }
}

contract usingCanvasBoundaries {
  uint private g_block;
  uint private max_max_index;
  uint private max_block_number;
  uint[] private halving;
   
  function usingCanvasBoundaries() internal {
    g_block = block.number;
    max_max_index = 4198401;
    max_block_number = g_block + 3330049;
    halving = [g_block + 16384, g_block + 81920, g_block + 770048];
  }

  function max_index() internal view returns(uint m_index) {
    if (block.number > max_block_number)
      return max_max_index;
    uint delta = block.number - g_block;
    return delta +
    ((block.number <= halving[0]) ? delta : halving[0] - g_block) +
    ((block.number <= halving[1]) ? delta : halving[1] - g_block) +
    ((block.number <= halving[2]) ? delta : halving[2] - g_block);
  }

  function HalvingInfo() public view returns(uint genesis_block, uint[] halving_array) {
    return (g_block, halving);
  }
}

contract Etherpixels is usingOwnership, usingCanvasBoundaries {
  uint private starting_price = 5000000000000; /* 5000 gwei */

  /* packed to 32 bytes */
  struct Pixel {
    uint96 price;
    address owner;
  }
  
  mapping(uint => Pixel) private pixels;

  event PixelPainted(uint i, address new_owner, address old_owner, uint price, bytes3 new_color);
  event PixelUnavailable(uint i, address new_owner, uint price, bytes3 new_color);
  
  function Paint(uint _index, bytes3 _color) public payable {
    require(_index <= max_index());
    paint_pixel(_index, _color, msg.value);
  }

  function BatchPaint(uint8 _batch_size, uint[] _index, bytes3[] _color, uint[] _paid) public payable {
    uint remaining = msg.value;
    uint m_i = max_index();
    for(uint8 i = 0; i < _batch_size; i++) {
      require(remaining >= _paid[i] && _index[i] <= m_i);
      paint_pixel(_index[i], _color[i], _paid[i]);
      remaining -= _paid[i];
    }
  }

  function StartingPrice() public view returns(uint price) {
    return starting_price;
  }

  function LowerStartingPrice(uint _new_starting_price) onlyOwner public {
    require(_new_starting_price < starting_price);
    starting_price = _new_starting_price;
  }
  
  function paint_pixel(uint _index, bytes3 _color, uint _paid) private {
    Pixel storage p = pixels[_index];
    if (msg.sender == p.owner) {
      PixelPainted(_index, msg.sender, msg.sender, p.price, _color);
    }
    else {
      uint current_price = p.price == 0 ? starting_price : uint(p.price);
      if (_paid < current_price * 11 / 10)
        PixelUnavailable(_index, msg.sender, current_price, _color);
      else {
        if (_paid > current_price * 2)
          _paid = current_price * 2;
        p.price = uint96(_paid);
        require(p.price == _paid); /* casting guard */ 
        address old_owner = p.owner;
        p.owner = msg.sender;
        PixelPainted(_index, msg.sender, old_owner, p.price, _color);
        if (old_owner != address(0))
          old_owner.send(_paid * 98 / 100); /* not using transfer to avoid old_owner locking pixel by buying it from a contract that reverts when receiving funds */
      }
    }
  }
}