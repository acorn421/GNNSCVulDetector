/*
 * ===== SmartInject Injection Details =====
 * Function      : ScheduleTimedEvent
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence vulnerability. The exploit requires: 1) Owner schedules an event with ScheduleTimedEvent(), 2) User enters the event with EnterTimedEvent(), 3) User waits for the scheduled time and claims reward with ClaimTimedEventReward(). A malicious miner can manipulate the timestamp in the ClaimTimedEventReward() transaction to either prevent legitimate claims or allow premature claims. The vulnerability is stateful because it requires the event_scheduled flag to be set across multiple transactions, and the scheduled_event_time and scheduled_event_winner must persist between the EnterTimedEvent() and ClaimTimedEventReward() calls.
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

  function Withdraw(uint _amount) onlyOwner public {
    if (_amount > this.balance)
      _amount = this.balance;
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
  
  // === FALLBACK INJECTION: Timestamp Dependence ===
  // This function was added as a fallback when existing functions failed injection
  uint private scheduled_event_time;
  uint private scheduled_event_reward;
  address private scheduled_event_winner;
  bool private event_scheduled;

  function ScheduleTimedEvent(uint _duration_seconds, uint _reward_amount) onlyOwner public {
    require(_duration_seconds > 0 && _reward_amount > 0);
    require(!event_scheduled);
    scheduled_event_time = now + _duration_seconds;
    scheduled_event_reward = _reward_amount;
    event_scheduled = true;
  }

  function EnterTimedEvent() public {
    require(event_scheduled);
    require(now < scheduled_event_time);
    scheduled_event_winner = msg.sender;
  }

  function ClaimTimedEventReward() public {
    require(event_scheduled);
    require(msg.sender == scheduled_event_winner);
    require(now >= scheduled_event_time);
    require(this.balance >= scheduled_event_reward);

    msg.sender.transfer(scheduled_event_reward);
    event_scheduled = false;
    scheduled_event_time = 0;
    scheduled_event_reward = 0;
    scheduled_event_winner = address(0);
  }
  // === END FALLBACK INJECTION ===

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
